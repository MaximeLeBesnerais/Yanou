//! Native tunnel core for Yanou.
//!
//! Scope of this build: prove the pipe the rest of the port depends on — that the fd
//! returned by `VpnConnection.create` can be read by Rust, that a default route into
//! the tunnel actually captures packets, and that the relay socket created here can be
//! exempted with `protect()`. There is no WireGuard handshake yet; `gotatun` lands on
//! top of the same fd once this is verified on the device.
//!
//! The C ABI is deliberately small and allocation-free at the boundary: strings in,
//! numbers out, JSON written into a caller-supplied buffer.

// The exported C ABI takes raw pointers from the NAPI shim. Marking these functions
// `unsafe` would not change the C side and would force every Rust caller, tests included,
// into an unsafe block, so the contract is stated here instead: each pointer is either
// null (handled by the callee) or a NUL-terminated string that outlives the call.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::CStr;
use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::os::raw::{c_char, c_int};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

mod api;
mod daita;
mod dns;
mod transports;
mod tunnel;

static STOP: AtomicBool = AtomicBool::new(false);
static PACKETS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
static RELAY_FD: AtomicI32 = AtomicI32::new(-1);
static STARTED: Mutex<Option<Instant>> = Mutex::new(None);
static LAST_DST: Mutex<[u8; 4]> = Mutex::new([0, 0, 0, 0]);
static RELAY: Mutex<Option<UdpSocket>> = Mutex::new(None);
/// The TCP counterpart of [`RELAY`], for transports that ride a TCP stream (udp2tcp).
/// The socket is deliberately unconnected until the transport connects it after the
/// extension has called `protect()`; see [`mh_open_relay_socket`].
static RELAY_TCP: Mutex<Option<tokio::net::TcpSocket>> = Mutex::new(None);
static FILES_DIR: Mutex<String> = Mutex::new(String::new());
/// Diagnostics are opt-in: nothing is written to the log unless the user turns it on.
static DIAGNOSTICS: AtomicBool = AtomicBool::new(false);
/// Start of the current diagnostics section, so lines can be read as elapsed time from
/// the moment the connection attempt began instead of as absolute wall-clock stamps.
static SECTION_START: Mutex<Option<Instant>> = Mutex::new(None);

/// Destination used by the self-test probes. It is inside the tunnel subnet, so an
/// unprotected socket sending to it must come back out of the tun device.
const PROBE_DESTINATION: &str = "10.64.0.1:9000";
const PROBE_INTERVAL: Duration = Duration::from_secs(2);
const IDLE_SLEEP: Duration = Duration::from_millis(2);

pub(crate) fn files_dir() -> Option<String> {
    FILES_DIR.lock().ok().map(|guard| guard.clone()).filter(|dir| !dir.is_empty())
}

#[no_mangle]
pub extern "C" fn mh_set_diagnostics(enabled: i32) {
    DIAGNOSTICS.store(enabled != 0, Ordering::SeqCst);
}

/// Starts a new diagnostics section, so each connection is readable on its own.
#[no_mangle]
pub extern "C" fn mh_log_marker(text: *const c_char) -> c_int {
    let Some(text) = (if text.is_null() { None } else {
        Some(unsafe { CStr::from_ptr(text) }.to_string_lossy().into_owned())
    }) else {
        return -1;
    };
    if let Ok(mut guard) = SECTION_START.lock() {
        *guard = Some(Instant::now());
    }
    write_line(&format!("=== {text} ==="));
    0
}

/// Appends one line to the current diagnostics section (no-op when diagnostics are off).
#[no_mangle]
pub extern "C" fn mh_log_line(text: *const c_char) -> c_int {
    if text.is_null() {
        return -1;
    }
    let text = unsafe { CStr::from_ptr(text) }.to_string_lossy().into_owned();
    log_line(&text);
    0
}

/// Marks the tunnel clock as started, which is what the UI shows as uptime.
pub(crate) fn note_started() {
    if let Ok(mut guard) = STARTED.lock() {
        *guard = Some(Instant::now());
    }
}

pub(crate) fn diagnostics_enabled() -> bool {
    DIAGNOSTICS.load(Ordering::Relaxed)
}

/// Appends one line to `yanou-native.log`, only while diagnostics are enabled.
fn log_line(message: &str) {
    if !diagnostics_enabled() {
        return;
    }
    // Inside a section, `+3.2s` is more useful than a timestamp repeated on every line.
    let prefix = SECTION_START
        .lock()
        .ok()
        .and_then(|guard| *guard)
        .map(|started| format!("+{:.1}s ", started.elapsed().as_secs_f32()))
        .unwrap_or_default();
    write_line(&format!("{prefix}{message}"));
}

fn write_line(line: &str) {
    let dir = match FILES_DIR.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => return,
    };
    if dir.is_empty() {
        return;
    }
    let path = format!("{dir}/yanou-native.log");
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line}");
    }
}

pub(crate) fn write_out(out: *mut c_char, capacity: c_int, text: &str) -> c_int {
    if out.is_null() || capacity <= 0 {
        return -1;
    }
    let bytes = text.as_bytes();
    let length = bytes.len().min(capacity as usize - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, length);
        *out.add(length) = 0;
    }
    length as c_int
}

#[no_mangle]
pub extern "C" fn mh_init(dir: *const c_char) -> c_int {
    if dir.is_null() {
        return -1;
    }
    let path = unsafe { CStr::from_ptr(dir) }.to_string_lossy().into_owned();
    if let Ok(mut guard) = FILES_DIR.lock() {
        *guard = path.clone();
    }
    log_line(&format!("init files_dir={path}"));
    0
}

const KEY_FILE: &str = "wireguard.key";

fn key_path() -> Option<std::path::PathBuf> {
    let dir = FILES_DIR.lock().ok()?.clone();
    if dir.is_empty() {
        return None;
    }
    Some(std::path::Path::new(&dir).join(KEY_FILE))
}

/// Loads the WireGuard private key, creating it on first use.
///
/// The private key never leaves this process: ArkTS only ever receives the public key,
/// which is what device registration needs. Keeping it in a file rather than preferences
/// also keeps it out of any backup of the key-value store.
/// Reads the key without ever creating one; `None` means no usable key is stored.
pub(crate) fn load_key() -> Option<[u8; 32]> {
    let path = key_path()?;
    let encoded = std::fs::read_to_string(&path).ok()?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

pub(crate) fn load_or_create_key() -> Option<[u8; 32]> {
    let path = key_path()?;
    if let Ok(encoded) = std::fs::read_to_string(&path) {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return Some(key);
            }
        }
        log_line("existing key file is not a 32-byte base64 key; regenerating");
    }

    let secret = StaticSecret::random_from_rng(OsRng);
    let encoded = base64::engine::general_purpose::STANDARD.encode(secret.to_bytes());
    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
    {
        Ok(mut file) => {
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
            if let Err(error) = file.write_all(encoded.as_bytes()) {
                log_line(&format!("key write failed: {error}"));
                return None;
            }
            log_line("generated a new WireGuard key");
        }
        Err(error) => {
            log_line(&format!("key open failed @ {}: {error}", path.display()));
            return None;
        }
    }
    Some(secret.to_bytes())
}

/// Returns `{"publicKey":"<base64>"}`, the value the device registration sends.
#[no_mangle]
pub extern "C" fn mh_wg_key(out: *mut c_char, capacity: c_int) -> c_int {
    let secret = match load_or_create_key() {
        Some(secret) => secret,
        None => return -1,
    };
    let public = PublicKey::from(&StaticSecret::from(secret));
    let encoded = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
    log_line(&format!("wg public key {}", &encoded[..encoded.len().min(16)]));
    let json = format!("{{\"publicKey\":\"{encoded}\"}}");
    write_out(out, capacity, &json)
}

#[no_mangle]
pub extern "C" fn mh_open_udp(host: *const c_char, port: c_int) -> c_int {
    if host.is_null() || port <= 0 {
        return -1;
    }
    let endpoint = unsafe { CStr::from_ptr(host) }.to_string_lossy().into_owned();
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => socket,
        Err(error) => {
            log_line(&format!("relay bind failed: {error}"));
            return -2;
        }
    };
    if let Err(error) = socket.connect((endpoint.as_str(), port as u16)) {
        log_line(&format!("relay connect {endpoint}:{port} failed: {error}"));
        return -3;
    }
    let fd = socket.as_raw_fd();
    log_line(&format!("relay socket {endpoint}:{port} fd={fd}"));
    if let Ok(mut guard) = RELAY.lock() {
        *guard = Some(socket);
    }
    RELAY_FD.store(fd, Ordering::SeqCst);
    fd
}

/// Creates the WireGuard transport socket as an *unconnected* IPv4 socket.
///
/// The caller is expected to hand the returned fd to `VpnConnection.protect()` and then
/// start the tunnel, which takes ownership of it. It is deliberately unconnected:
/// `gotatun` addresses every datagram explicitly, and `send_to` fails on a connected
/// UDP socket.
/// Reads the stored key **without** creating one, answering `{"publicKey":"…"}` or
/// `{"publicKey":""}` when there is none.
///
/// The tunnel must never mint a key: only the sign-in flow may create one, because only
/// it registers the key with the account. A key generated here would be silently unknown
/// to the relay and every handshake would be dropped.
#[no_mangle]
pub extern "C" fn mh_wg_key_readonly(out: *mut c_char, capacity: c_int) -> c_int {
    let encoded = key_path()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| {
            base64::engine::general_purpose::STANDARD
                .decode(text.trim())
                .ok()
                .filter(|bytes| bytes.len() == 32)
        })
        .map(|bytes| {
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&bytes);
            let public = PublicKey::from(&StaticSecret::from(secret));
            base64::engine::general_purpose::STANDARD.encode(public.as_bytes())
        })
        .unwrap_or_default();
    write_out(out, capacity, &format!("{{\"publicKey\":\"{encoded}\"}}"))
}

/// Deletes the stored key and creates a fresh one.
///
/// Mullvad does not want a key reused across device registrations, so every sign-in
/// rotates it. Returns the same JSON shape as `mh_wg_key`.
#[no_mangle]
pub extern "C" fn mh_rotate_key(out: *mut c_char, capacity: c_int) -> c_int {
    if let Some(path) = key_path() {
        match std::fs::remove_file(&path) {
            Ok(()) => log_line("deleted the previous WireGuard key"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => log_line(&format!("old key delete failed: {error}")),
        }
    }
    mh_wg_key(out, capacity)
}

/// Removes the key file. Called on sign-out, after the device is deleted.
#[no_mangle]
pub extern "C" fn mh_clear_key() -> c_int {
    let Some(path) = key_path() else {
        return -1;
    };
    match std::fs::remove_file(&path) {
        Ok(()) => {
            log_line("deleted the WireGuard key on sign-out");
            0
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => {
            log_line(&format!("key delete failed: {error}"));
            -1
        }
    }
}

/// Opens the relay socket for one connection attempt and stores it for [`mh_tunnel_start`].
///
/// # Socket contract
///
/// The extension creates the socket, gets its fd back, and passes that fd to
/// `VpnConnection.protect()`; the core owns the socket from creation and the transport
/// consumes it from `take_relay_socket()`. One socket per attempt, and its kind is fixed
/// by the transport the extension is about to name in `mh_tunnel_start`:
///
/// * `proto == 0` (`'udp'`, the default): a bound, **unconnected**, non-blocking UDP
///   socket in the relay's address family. `direct` and `shadowsocks` take this one.
/// * `proto == 1` (`'tcp'`): a bound, **unconnected**, non-blocking TCP socket in the same
///   family, which `udp2tcp` connects to the relay's TCP listener (`peer` = relay address
///   + the port from its `{"port":n}` settings). It must stay unconnected until after
///   `protect()`: a connect before that would pick the route that is about to become the
///   tunnel, and the stream would loop back into the device.
///
/// The core picks the slot by transport name in [`take_relay_socket`]; opening a socket
/// drops whatever an earlier attempt left behind, so an unclaimed fd never lingers.
#[no_mangle]
pub extern "C" fn mh_open_relay_socket(family: c_int, proto: c_int) -> c_int {
    // One attempt owns at most one relay socket. Drop any socket a previous attempt
    // created but never reached `tunnelStart` (a refused attempt, for example).
    if let Ok(mut guard) = RELAY.lock() {
        *guard = None;
    }
    if let Ok(mut guard) = RELAY_TCP.lock() {
        *guard = None;
    }
    if proto == 0 {
        open_relay_udp(family)
    } else {
        open_relay_tcp(family)
    }
}

/// Binds the unconnected UDP socket `direct` and `shadowsocks` send on.
fn open_relay_udp(family: c_int) -> c_int {
    // The relay is reached over IPv6 when the host has a global address; the IPv4
    // listener is bound to the matching family so `send_to` never mixes families.
    let bind = if family == 6 { "[::]:0" } else { "0.0.0.0:0" };
    let socket = match UdpSocket::bind(bind) {
        Ok(socket) => socket,
        Err(error) => {
            log_line(&format!("relay socket bind failed: {error}"));
            return -2;
        }
    };
    if let Err(error) = socket.set_nonblocking(true) {
        log_line(&format!("relay socket nonblocking failed: {error}"));
        return -3;
    }
    let fd = socket.as_raw_fd();
    if let Ok(mut guard) = RELAY.lock() {
        *guard = Some(socket);
    }
    RELAY_FD.store(fd, Ordering::SeqCst);
    log_line(&format!("relay socket fd={fd} family={} (unconnected, awaiting protect)", if family == 6 { "ipv6" } else { "ipv4" }));
    fd
}

/// Binds the unconnected TCP socket `udp2tcp` connects to the relay.
///
/// Tokio sockets are non-blocking from creation and register with the reactor only when
/// they are turned into a stream, so creating this outside the runtime is safe.
fn open_relay_tcp(family: c_int) -> c_int {
    let socket = match if family == 6 {
        tokio::net::TcpSocket::new_v6()
    } else {
        tokio::net::TcpSocket::new_v4()
    } {
        Ok(socket) => socket,
        Err(error) => {
            log_line(&format!("relay tcp socket create failed: {error}"));
            return -2;
        }
    };
    let bind: SocketAddr = if family == 6 {
        SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
    };
    if let Err(error) = socket.bind(bind) {
        log_line(&format!("relay tcp socket bind failed: {error}"));
        return -2;
    }
    let fd = socket.as_raw_fd();
    if let Ok(mut guard) = RELAY_TCP.lock() {
        *guard = Some(socket);
    }
    RELAY_FD.store(fd, Ordering::SeqCst);
    log_line(&format!("relay tcp socket fd={fd} family={} (unconnected, awaiting protect)", if family == 6 { "ipv6" } else { "ipv4" }));
    fd
}

/// Hands the pre-created socket for `transport` to the tunnel engine, which owns it from
/// then on. The extension opened exactly one kind, so the transport name picks the slot.
pub(crate) fn take_relay_socket(transport: &str) -> Option<transports::RelaySocket> {
    if transport == "udp2tcp" {
        return RELAY_TCP
            .lock()
            .ok()
            .and_then(|mut guard| guard.take())
            .map(transports::RelaySocket::Tcp);
    }
    RELAY
        .lock()
        .ok()
        .and_then(|mut guard| guard.take())
        .map(transports::RelaySocket::Udp)
}

#[no_mangle]
pub extern "C" fn mh_attach_tun(fd: c_int, mtu: c_int) -> c_int {
    if fd < 0 {
        return -1;
    }
    let mut config = tun::Configuration::default();
    config
        .raw_fd(fd)
        .mtu(mtu as u16)
        // The fd belongs to the VpnConnection; closing it here would tear down the
        // system side when the reader thread exits.
        .close_fd_on_drop(false);

    let device = match tun::create(&config) {
        Ok(device) => device,
        Err(error) => {
            log_line(&format!("tun::create fd={fd} failed: {error}"));
            return -2;
        }
    };
    if let Err(error) = device.set_nonblock() {
        log_line(&format!("set_nonblock failed: {error}"));
        return -3;
    }

    STOP.store(false, Ordering::SeqCst);
    if let Ok(mut guard) = STARTED.lock() {
        *guard = Some(Instant::now());
    }
    log_line(&format!("tun attached fd={fd} mtu={mtu}"));
    log_line("no wireguard peer configured: this build captures and drops, it never handshakes");

    let _ = thread::Builder::new()
        .name("mh-tun".into())
        .spawn(move || read_loop(device));
    let _ = thread::Builder::new()
        .name("mh-probe".into())
        .spawn(probe_loop);
    0
}

fn read_loop(mut device: tun::Device) {
    let mut buffer = vec![0u8; 65_536];
    loop {
        if STOP.load(Ordering::Relaxed) {
            break;
        }
        match device.read(&mut buffer) {
            Ok(length) if length > 0 => {
                PACKETS.fetch_add(1, Ordering::Relaxed);
                BYTES.fetch_add(length as u64, Ordering::Relaxed);
                if length >= 20 && buffer[0] >> 4 == 4 {
                    let mut destination = [0u8; 4];
                    destination.copy_from_slice(&buffer[16..20]);
                    if let Ok(mut guard) = LAST_DST.lock() {
                        *guard = destination;
                    }
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(IDLE_SLEEP);
            }
            Err(error) => {
                log_line(&format!("tun read stopped: {error}"));
                break;
            }
        }
    }
    log_line("tun reader exited");
}

/// Sends a datagram on an unprotected socket. With 0.0.0.0/0 routed into the tunnel,
/// these packets are what the reader above is supposed to see.
fn probe_loop() {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => socket,
        Err(error) => {
            log_line(&format!("probe bind failed: {error}"));
            return;
        }
    };
    while !STOP.load(Ordering::Relaxed) {
        let _ = socket.send_to(&[0u8; 32], PROBE_DESTINATION);
        thread::sleep(PROBE_INTERVAL);
    }
}

#[no_mangle]
pub extern "C" fn mh_stats(out: *mut c_char, capacity: c_int) -> c_int {
    let uptime = STARTED
        .lock()
        .ok()
        .and_then(|guard| *guard)
        .map(|started| started.elapsed().as_millis())
        .unwrap_or(0);
    let destination = LAST_DST.lock().map(|guard| *guard).unwrap_or([0, 0, 0, 0]);
    let json = format!(
        "{{\"packets\":{},\"bytes\":{},\"protectedFd\":{},\"uptimeMs\":{},\"lastDst\":\"{}.{}.{}.{}\"}}",
        PACKETS.load(Ordering::Relaxed),
        BYTES.load(Ordering::Relaxed),
        RELAY_FD.load(Ordering::Relaxed),
        uptime,
        destination[0],
        destination[1],
        destination[2],
        destination[3]
    );
    write_out(out, capacity, &json)
}

#[no_mangle]
pub extern "C" fn mh_stop() {
    STOP.store(true, Ordering::SeqCst);
    if let Ok(mut guard) = RELAY.lock() {
        *guard = None;
    }
    if let Ok(mut guard) = RELAY_TCP.lock() {
        *guard = None;
    }
    RELAY_FD.store(-1, Ordering::SeqCst);
    if let Ok(mut guard) = STARTED.lock() {
        *guard = None;
    }
    log_line("stop requested");
}
