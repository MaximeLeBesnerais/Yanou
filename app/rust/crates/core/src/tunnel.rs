//! WireGuard engine.
//!
//! `gotatun` is the same engine Mullvad's own clients use. This module wires it to the
//! fd the system handed us and reports the two things the UI needs: whether a handshake
//! completed, and how much traffic the peer has actually moved. A handshake is asked for
//! explicitly, because gotatun only initiates one when there is traffic to send — and a
//! tunnel that no application is using yet has none.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use gotatun::device::{DeviceBuilder, Peer};
use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::tun_async_device::TunDevice;
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};
use serde_json::json;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::obfs::TransportFactory;
use crate::{api::runtime, log_line, note_started, write_out};

static RUNNING: AtomicBool = AtomicBool::new(false);
/// Set when gotatun reports a completed handshake with the relay.
static HANDSHAKE: AtomicBool = AtomicBool::new(false);
static RX_BYTES: AtomicU64 = AtomicU64::new(0);
static TX_BYTES: AtomicU64 = AtomicU64::new(0);
/// Age of the most recent key exchange, capped at an hour.
///
/// This is the only signal that separates "the tunnel is alive but idle" from "the relay
/// stopped answering while the engine keeps sending keepalives". A live session rekeys
/// every couple of minutes, so a large age means nothing is coming back any more.
static HANDSHAKE_AGE_MS: AtomicU64 = AtomicU64::new(3_600_000);
/// Which families to forward: bit 1 IPv4, bit 2 IPv6. Default is both.
static IP_VERSION: AtomicU64 = AtomicU64::new(FAMILY_IPV4 | FAMILY_IPV6);
const FAMILY_IPV4: u64 = 1;
const FAMILY_IPV6: u64 = 2;
static JOBS: Mutex<Vec<tokio::task::JoinHandle<()>>> = Mutex::new(Vec::new());
static LAST_ERROR: Mutex<String> = Mutex::new(String::new());

/// How long a relay gets to answer a handshake before the next candidate is tried.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Peer statistics are cheap; polling them keeps the counters live in the UI.
const STATS_INTERVAL: Duration = Duration::from_millis(500);
/// Reported instead of a real age when this session has never completed a key exchange.
const NO_HANDSHAKE_AGE_MS: u64 = 3_600_000;
/// When to ask for a fresh key exchange.
///
/// WireGuard rejects a session that has not rekeyed within 180 s, and gotatun only
/// rekeys when real payload flows, so a tunnel nobody is using dies after three quiet
/// minutes. Asking just before that keeps an idle tunnel usable.
const REKEY_AFTER_MS: u64 = 100_000;

/// Counts packets coming out of WireGuard, so the UI can tell "blocking" from "tunnelling".
#[derive(Clone)]
struct ObservedTun {
    inner: TunDevice,
}

impl IpSend for ObservedTun {
    fn send(&mut self, packet: Packet<Ip>) -> impl std::future::Future<Output = io::Result<()>> + Send {
        self.inner.send(packet)
    }
}

impl IpRecv for ObservedTun {
    fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> impl std::future::Future<
        Output = io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a>,
    > + Send {
        self.inner.recv(pool)
    }

    fn mtu(&self) -> MtuWatcher {
        self.inner.mtu()
    }
}

fn decode_key(encoded: &str, what: &str) -> Result<[u8; 32], String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|error| format!("{what}: {error}"))?;
    if bytes.len() != 32 {
        return Err(format!("{what}: expected 32 bytes, got {}", bytes.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn set_error(message: impl Into<String>) {
    let message = message.into();
    log_line(&format!("tunnel: {message}"));
    if let Ok(mut guard) = LAST_ERROR.lock() {
        *guard = message;
    }
}

/// Can the relay be reached over TCP at all?
///
/// If a handshake on every UDP port gets no answer, this separates "the IP is dropped"
/// from "UDP is dropped": a refused connection still proves the IP is reachable.
fn probe_tcp(ip: std::net::IpAddr, port: u16) -> String {
    let target = SocketAddr::new(ip, port);
    match std::net::TcpStream::connect_timeout(&target, Duration::from_secs(3)) {
        Ok(_) => "connected".to_string(),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => "refused".to_string(),
        Err(error) if error.kind() == io::ErrorKind::TimedOut => "timed out".to_string(),
        Err(error) => format!("{error}"),
    }
}

/// Sends a DNS query for `mullvad.net` on the socket the engine is about to use.
///
/// This proves the protected socket can reach the internet while the tunnel owns the
/// default route. If it times out, the handshake was never the problem: the datagrams
/// never left the device.
fn probe_relay_socket(socket: &std::net::UdpSocket) -> (bool, bool) {
    // "mullvad" is seven characters: [7, 'm', 'u', 'l', 'l', 'v', 'a', 'd'].
    const QUERY: [u8; 29] = [
        0x4d, 0x48, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7, b'm', b'u', b'l', b'l', b'v', b'a', b'd',
        3, b'n', b'e', b't',
        0, 0x00, 0x01, 0x00, 0x01,
    ];
    let target: SocketAddr = if socket.local_addr().map(|addr| addr.is_ipv6()).unwrap_or(false) {
        "[2606:4700:4700::1111]:53".parse().expect("valid dns address")
    } else {
        "1.1.1.1:53".parse().expect("valid dns address")
    };
    let sent = socket.send_to(&QUERY, target).is_ok();
    let mut buffer = [0u8; 512];
    let received = matches!(socket.recv_from(&mut buffer), Ok((length, _)) if length >= 12);
    (sent, received)
}

fn cstr(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { std::ffi::CStr::from_ptr(ptr) }.to_string_lossy().into_owned())
}

#[no_mangle]
pub extern "C" fn mh_tunnel_start(
    fd: c_int,
    mtu: c_int,
    peer_key: *const c_char,
    endpoint_ip: *const c_char,
    endpoint_port: c_int,
    bridge: *const c_char,
    out: *mut c_char,
    capacity: c_int,
) -> c_int {
    let (Some(peer_key), Some(endpoint_ip)) = (cstr(peer_key), cstr(endpoint_ip)) else {
        return write_out(out, capacity, "{\"ok\":false,\"error\":\"missing arguments\"}");
    };
    if fd < 0 || endpoint_port <= 0 {
        return write_out(out, capacity, "{\"ok\":false,\"error\":\"bad fd or port\"}");
    }

    // Never mint a key here: an unregistered key is silently dropped by the relay.
    let secret = match crate::load_key() {
        Some(key) => StaticSecret::from(key),
        None => {
            return write_out(
                out,
                capacity,
                "{\"ok\":false,\"error\":\"no registered device key; sign in again\"}",
            )
        }
    };
    log_line(&format!("tunnel: peer key {}", &peer_key[..peer_key.len().min(8)]));
    let relay_key = match decode_key(&peer_key, "peer key") {
        Ok(key) => PublicKey::from(key),
        Err(error) => {
            return write_out(out, capacity, &json!({"ok": false, "error": error}).to_string())
        }
    };
    let endpoint_text = if endpoint_ip.contains(':') {
        format!("[{endpoint_ip}]:{endpoint_port}")
    } else {
        format!("{endpoint_ip}:{endpoint_port}")
    };
    let endpoint: SocketAddr = match endpoint_text.parse() {
        Ok(addr) => addr,
        Err(error) => {
            return write_out(out, capacity, &json!({"ok": false, "error": error.to_string()}).to_string())
        }
    };

    // Dropping the previous device deregisters the tun fd from the reactor. Aborted
    // tasks are dropped on a runtime worker, so give that a moment before registering
    // the same fd again for the next candidate.
    if stop_running() {
        std::thread::sleep(Duration::from_millis(80));
    }
    let bridge: Option<SocketAddr> = cstr(bridge).and_then(|text| {
        if text.is_empty() {
            return None;
        }
        match text.parse() {
            Ok(addr) => Some(addr),
            Err(error) => {
                log_line(&format!("bridge endpoint {text} is not usable: {error}"));
                None
            }
        }
    });

    HANDSHAKE.store(false, Ordering::SeqCst);
    RX_BYTES.store(0, Ordering::SeqCst);
    TX_BYTES.store(0, Ordering::SeqCst);
    crate::obfs::reset_counters();
    if let Ok(mut guard) = LAST_ERROR.lock() {
        guard.clear();
    }
    log_line(&format!("tunnel: starting to {endpoint}"));

    // Everything that touches the tun or the reactor has to run inside the runtime:
    // `tun::AsyncDevice::new` registers the fd with the reactor and panics without one.
    let outcome = runtime().block_on(async move {
        let Some(std_socket) = crate::take_relay_socket() else {
            return Err::<_, String>(
                "no relay socket: the extension must open and protect one first".into(),
            );
        };
        if let Ok(local) = std_socket.local_addr() {
            log_line(&format!("relay socket bound to {local}"));
        }

        // The probe needs a blocking socket; tokio wants the opposite.
        let _ = std_socket.set_nonblocking(false);
        let _ = std_socket.set_read_timeout(Some(Duration::from_secs(1)));
        let (sent, received) = probe_relay_socket(&std_socket);
        log_line(&format!("self-test: dns query sent={sent} reply={received}"));
        let tcp = probe_tcp(endpoint.ip(), 443);
        log_line(&format!("self-test: tcp {}:443 {tcp}", endpoint.ip()));
        std_socket
            .set_nonblocking(true)
            .map_err(|error| format!("relay socket nonblocking: {error}"))?;

        let udp_socket = tokio::net::UdpSocket::from_std(std_socket)
            .map_err(|error| format!("relay socket: {error}"))?;
        let transport = TransportFactory::new(udp_socket, endpoint, bridge)?;

        let mut config = tun::Configuration::default();
        config.raw_fd(fd).mtu(mtu as u16).close_fd_on_drop(false);
        let device = tun::create(&config).map_err(|error| error.to_string())?;
        let async_device = tun::AsyncDevice::new(device).map_err(|error| error.to_string())?;
        let tun_device = TunDevice::from_tun_device(async_device).map_err(|error| error.to_string())?;

        // A family that is not selected is still routed into the tun by the system, but it
        // is left out of the peer's allowed IPs, so gotatun drops it instead of forwarding
        // it. That is leak protection: it fails inside the tunnel, never on the carrier.
        let families = IP_VERSION.load(Ordering::SeqCst);
        let mut allowed_ips = Vec::new();
        if families & FAMILY_IPV4 != 0 {
            match ipnetwork::IpNetwork::new(Ipv4Addr::UNSPECIFIED.into(), 0) {
                Ok(network) => allowed_ips.push(network),
                Err(error) => log_line(&format!("tunnel: bad allowed ip: {error}")),
            }
        }
        if families & FAMILY_IPV6 != 0 {
            match ipnetwork::IpNetwork::new(Ipv6Addr::UNSPECIFIED.into(), 0) {
                Ok(network) => allowed_ips.push(network),
                Err(error) => log_line(&format!("tunnel: bad allowed ip: {error}")),
            }
        }
        log_line(&format!("tunnel: forwarding families 0x{families:x}"));

        let mut relay = Peer::new(relay_key)
            .with_endpoint(endpoint)
            .with_allowed_ips(allowed_ips);
        // Mullvad relays expect a keepalive; NAT traversal without one is unreliable.
        relay.keepalive = Some(25);

        let device = Arc::new(
            DeviceBuilder::new()
                .with_ip(ObservedTun { inner: tun_device })
                .with_udp(transport)
                .with_private_key(secret)
                .with_peer(relay)
                .build()
                .await
                .map_err(|error| error.to_string())?,
        );

        log_line("tunnel: device up, asking for a handshake");
        log_line(&format!(
            "tunnel: peer endpoint {endpoint}, handshake timeout {} s",
            HANDSHAKE_TIMEOUT.as_secs()
        ));
        let mut jobs = Vec::new();

        // Without this nothing is sent until an application happens to generate traffic,
        // so an idle tunnel would never handshake and the UI would never leave "connecting".
        let handshake_device = device.clone();
        jobs.push(tokio::spawn(async move {
            let outcome = tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                handshake_device.force_handshake(&relay_key),
            )
            .await;
            match outcome {
                Ok(Ok(())) => {
                    HANDSHAKE.store(true, Ordering::SeqCst);
                    log_line("tunnel: handshake complete");
                }
                Ok(Err(error)) => set_error(format!("handshake failed: {error}")),
                // The poller below still notices a late handshake; this only ends the wait.
                Err(_) => log_line("tunnel: no handshake within 5 s, retrying next candidate"),
            }
        }));

        let stats_device = device.clone();
        jobs.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(STATS_INTERVAL);
            loop {
                ticker.tick().await;
                let peers = stats_device.peers().await;
                let mut rx = 0u64;
                let mut tx = 0u64;
                let mut handshake = false;
                let mut age_ms: u64 = NO_HANDSHAKE_AGE_MS;
                for entry in &peers {
                    rx = rx.saturating_add(entry.stats.rx_bytes as u64);
                    tx = tx.saturating_add(entry.stats.tx_bytes as u64);
                    if let Some(age) = entry.stats.last_handshake {
                        handshake = true;
                        age_ms = age_ms.min(age.as_millis() as u64);
                    }
                }
                RX_BYTES.store(rx, Ordering::Relaxed);
                TX_BYTES.store(tx, Ordering::Relaxed);
                if age_ms >= REKEY_AFTER_MS && age_ms < REKEY_AFTER_MS + 1000 {
                    // Only the tick that crosses the threshold asks, so a failing relay is
                    // retried by the handshake task rather than flooded from here.
                    let _ = stats_device.force_handshake(&relay_key).await;
                }
                HANDSHAKE_AGE_MS.store(age_ms, Ordering::Relaxed);
                if handshake && !HANDSHAKE.swap(true, Ordering::SeqCst) {
                    log_line("tunnel: handshake confirmed by peer stats");
                }
            }
        }));

        Ok::<_, String>(jobs)
    });

    match outcome {
        Ok(jobs) => {
            RUNNING.store(true, Ordering::SeqCst);
            note_started();
            if let Ok(mut guard) = JOBS.lock() {
                *guard = jobs;
            }
            write_out(
                out,
                capacity,
                &json!({"ok": true, "endpoint": endpoint.to_string()}).to_string(),
            )
        }
        Err(error) => {
            set_error(format!("device setup failed: {error}"));
            write_out(out, capacity, &json!({"ok": false, "error": error}).to_string())
        }
    }
}

/// Aborts the running jobs and reports whether there was anything to stop.
fn stop_running() -> bool {
    let mut stopped = false;
    if let Ok(mut guard) = JOBS.lock() {
        for job in guard.drain(..) {
            job.abort();
            stopped = true;
        }
    }
    RUNNING.store(false, Ordering::SeqCst);
    stopped
}

#[no_mangle]
pub extern "C" fn mh_tunnel_stop() {
    // Dropping the previous device deregisters the tun fd from the reactor. Aborted
    // tasks are dropped on a runtime worker, so give that a moment before registering
    // the same fd again for the next candidate.
    if stop_running() {
        std::thread::sleep(Duration::from_millis(80));
    }
    HANDSHAKE.store(false, Ordering::SeqCst);
    HANDSHAKE_AGE_MS.store(NO_HANDSHAKE_AGE_MS, Ordering::SeqCst);
    log_line("tunnel: stopped");
}

#[no_mangle]
pub extern "C" fn mh_set_ip_version(families: c_int) {
    let value = families as u64 & (FAMILY_IPV4 | FAMILY_IPV6);
    // Forwarding nothing would be a black hole with the VPN still claiming to be up.
    IP_VERSION.store(if value == 0 { FAMILY_IPV4 } else { value }, Ordering::SeqCst);
}

#[no_mangle]
pub extern "C" fn mh_tunnel_status(out: *mut c_char, capacity: c_int) -> c_int {
    let error = LAST_ERROR.lock().map(|guard| guard.clone()).unwrap_or_default();
    let payload = json!({
        "running": RUNNING.load(Ordering::SeqCst),
        "handshake": HANDSHAKE.load(Ordering::SeqCst),
        "udpSent": crate::obfs::counters().0,
        "udpRecv": crate::obfs::counters().1,
        "inbound": HANDSHAKE.load(Ordering::SeqCst),
        "rxBytes": RX_BYTES.load(Ordering::Relaxed),
        "txBytes": TX_BYTES.load(Ordering::Relaxed),
        "handshakeAgeMs": HANDSHAKE_AGE_MS.load(Ordering::Relaxed),
        "error": error,
    });
    write_out(out, capacity, &payload.to_string())
}
