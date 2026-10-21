//! WireGuard engine.
//!
//! `gotatun` is the same engine Mullvad's own clients use. This module wires it to the
//! fd the system handed us and reports the two things the UI needs: whether a handshake
//! completed, and how much traffic the peer has actually moved. A handshake is asked for
//! explicitly, because gotatun only initiates one when there is traffic to send — and a
//! tunnel that no application is using yet has none.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use gotatun::device::{Device, DeviceBuilder, DeviceTransports, Peer};
use gotatun::noise::TimerParams;
use gotatun::packet::{Ip, Ipv4Header, Ipv6Header, Packet, PacketBufPool, UdpHeader, WgData};
use gotatun::tun::tun_async_device::TunDevice;
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};
use gotatun::udp::channel::new_udp_tun_channel;
use ipnetwork::IpNetwork;
use serde::Deserialize;
use serde_json::json;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::transports::TransportFactory;
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
/// True while the running tunnel is the two-device multihop chain.
static MULTIHOP: AtomicBool = AtomicBool::new(false);
/// MTU the engine actually configured, after the second WireGuard header is removed.
static EFFECTIVE_MTU: AtomicU64 = AtomicU64::new(0);

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
/// The smallest MTU a multihop tunnel is allowed to configure.
///
/// The second WireGuard header is subtracted from the requested MTU, but IPv6 needs 1280
/// bytes end to end: below it, large packets silently stop arriving.
const MIN_MULTIHOP_MTU: u16 = 1280;
/// Buffers between the entry and the exit device, in packets. The upstream value.
const PACKET_CHANNEL_CAPACITY: usize = 100;

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

/// The per-attempt settings JSON the extension sends alongside the transport name.
///
/// The core owns the multihop keys today. Transport units add their own keys at the same
/// level and unknown keys are ignored, so they do not have to coordinate here.
#[derive(Default, Deserialize)]
struct TunnelSettings {
    /// Exit relay of a multihop chain; absent or null for a single hop.
    #[serde(default)]
    exit: Option<ExitSettings>,
    /// The tunnel address the account assigned to this device, e.g. `10.170.64.72`.
    /// It is the source of the packets the exit device hands to the entry device; the
    /// gateway (`10.64.0.1`) is a different address.
    #[serde(default, rename = "sourceIpv4")]
    source_ipv4: Option<String>,
}

/// The exit relay of a multihop chain, exactly as the UI selected it.
#[derive(Deserialize)]
struct ExitSettings {
    ip: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(default = "default_exit_port")]
    port: u16,
    /// Only used in logs; the engine addresses the relay by IP.
    #[serde(default)]
    hostname: String,
}

/// The port an exit relay accepts multihop connections on, independent of the entry port
/// the ladder picks for this attempt.
fn default_exit_port() -> u16 {
    51820
}

/// A resolved exit peer.
struct ExitPeer {
    endpoint: SocketAddr,
    key: PublicKey,
    hostname: String,
}

impl ExitPeer {
    /// Bytes the second WireGuard header adds to every payload packet: the outer IP header
    /// of the exit datagram, its UDP header, and the WireGuard data header with its tag.
    fn overhead(&self) -> u16 {
        let ip = if self.endpoint.is_ipv6() {
            Ipv6Header::LEN
        } else {
            Ipv4Header::LEN
        };
        (ip + UdpHeader::LEN + WgData::OVERHEAD) as u16
    }

    fn label(&self) -> String {
        if self.hostname.is_empty() {
            self.endpoint.to_string()
        } else {
            format!("{} ({})", self.hostname, self.endpoint)
        }
    }
}

/// MTU a multihop tunnel exposes to apps, after paying for the second WireGuard header.
///
/// Never below [`MIN_MULTIHOP_MTU`]: a smaller payload MTU would break IPv6 midsession,
/// which is harder to notice than a slightly smaller MTU.
fn multihop_mtu(requested: u16, overhead: u16) -> u16 {
    requested.saturating_sub(overhead).max(MIN_MULTIHOP_MTU)
}

/// Parses the attempt settings. Empty settings mean "no exit and no transport options".
fn parse_settings(raw: &str) -> Result<TunnelSettings, String> {
    if raw.trim().is_empty() {
        return Ok(TunnelSettings::default());
    }
    serde_json::from_str(raw).map_err(|error| format!("settings json: {error}"))
}

fn resolve_exit(settings: &TunnelSettings) -> Result<Option<ExitPeer>, String> {
    let Some(exit) = settings.exit.as_ref() else {
        return Ok(None);
    };
    let ip: IpAddr = exit
        .ip
        .trim()
        .parse()
        .map_err(|error| format!("exit address '{}': {error}", exit.ip))?;
    let key = PublicKey::from(decode_key(&exit.public_key, "exit peer key")?);
    Ok(Some(ExitPeer {
        endpoint: SocketAddr::new(
            ip,
            if exit.port == 0 { default_exit_port() } else { exit.port },
        ),
        key,
        hostname: exit.hostname.clone(),
    }))
}

/// Reads the assigned IPv4 tunnel address, tolerating the CIDR suffix the session stores.
fn parse_source_v4(raw: &Option<String>) -> Ipv4Addr {
    raw.as_deref()
        .map(|text| text.split('/').next().unwrap_or_default().trim())
        .and_then(|text| text.parse().ok())
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

/// Builds the peer for the entry or the exit relay.
fn make_peer(
    key: PublicKey,
    endpoint: SocketAddr,
    allowed_ips: Vec<IpNetwork>,
    timers: Option<TimerParams>,
) -> Peer {
    let mut peer = Peer::new(key)
        .with_endpoint(endpoint)
        .with_allowed_ips(allowed_ips);
    // Mullvad relays expect a keepalive; NAT traversal without one is unreliable.
    peer.keepalive = Some(25);
    // LWO v2 asks for timers that match the relay's obfuscation. Only the entry peer
    // speaks LWO; the exit peer crosses the entry tunnel as plain WireGuard.
    if let Some(timers) = timers {
        peer = peer.dangerously_with_timer_params(timers);
    }
    peer
}

/// Traffic counters and the oldest session of one device.
struct PeerSummary {
    rx: u64,
    tx: u64,
    sessions: usize,
    age: Option<Duration>,
}

async fn summarize<T: DeviceTransports>(device: &Device<T>) -> PeerSummary {
    let peers = device.peers().await;
    let mut summary = PeerSummary {
        rx: 0,
        tx: 0,
        sessions: 0,
        age: None,
    };
    for entry in &peers {
        summary.rx = summary.rx.saturating_add(entry.stats.rx_bytes as u64);
        summary.tx = summary.tx.saturating_add(entry.stats.tx_bytes as u64);
        if let Some(age) = entry.stats.last_handshake {
            summary.sessions += 1;
            summary.age = Some(match summary.age {
                Some(current) => current.max(age),
                None => age,
            });
        }
    }
    summary
}

/// Asks one device for a fresh key exchange just before its session expires.
///
/// Same guard as the single-hop path: only the tick that crosses the threshold asks, so a
/// dead relay is retried by WireGuard's own timers instead of being flooded from here.
async fn maybe_rekey<T: DeviceTransports>(
    device: &Device<T>,
    key: &PublicKey,
    age: Option<Duration>,
) {
    let Some(age) = age else {
        return;
    };
    let age_ms = age.as_millis() as u64;
    if age_ms >= REKEY_AFTER_MS && age_ms < REKEY_AFTER_MS + 1000 {
        // Bounded: a dead relay must not freeze the statistics loop that decides whether
        // the tunnel is still alive.
        let _ = tokio::time::timeout(HANDSHAKE_TIMEOUT, device.force_handshake(key)).await;
    }
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
    transport: *const c_char,
    settings: *const c_char,
    out: *mut c_char,
    capacity: c_int,
) -> c_int {
    let (Some(peer_key), Some(endpoint_ip)) = (cstr(peer_key), cstr(endpoint_ip)) else {
        return write_out(out, capacity, "{\"ok\":false,\"error\":\"missing arguments\"}");
    };
    if fd < 0 || endpoint_port <= 0 {
        return write_out(out, capacity, "{\"ok\":false,\"error\":\"bad fd or port\"}");
    }

    // Never mint a key here: an unregistered key is silently dropped by the relay. The
    // bytes are kept rather than the StaticSecret so both devices of a multihop chain can
    // be built from the same registered key.
    let secret_bytes = match crate::load_key() {
        Some(key) => key,
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

    // The transport is chosen by the extension: the ladder knows which one this attempt
    // is, and the engine only needs its name. Unknown names fail loudly here.
    let transport_name = cstr(transport).unwrap_or_else(|| "direct".to_string());
    // Per-transport settings the extension knows and the core does not: the QUIC token
    // and SNI, an LWO version, a udp2tcp port. Empty string when the transport has none.
    // The multihop exit rides in the same object, at the same level.
    let transport_settings = cstr(settings).unwrap_or_default();
    let parsed_settings = match parse_settings(&transport_settings) {
        Ok(settings) => settings,
        Err(error) => {
            return write_out(out, capacity, &json!({"ok": false, "error": error}).to_string())
        }
    };
    let exit_peer = match resolve_exit(&parsed_settings) {
        Ok(exit) => exit,
        Err(error) => {
            return write_out(out, capacity, &json!({"ok": false, "error": error}).to_string())
        }
    };
    let multihop = exit_peer.is_some();
    let source_v4 = parse_source_v4(&parsed_settings.source_ipv4);
    let requested_mtu = mtu as u16;
    // A multihop payload crosses two WireGuard headers. The extra one is spent on the exit
    // relay's outer IP/UDP/WG header, so the tun MTU comes down by that much; below 1280
    // IPv6 stops working, so that is the floor.
    let effective_mtu = if let Some(exit) = exit_peer.as_ref() {
        let overhead = exit.overhead();
        let reduced = multihop_mtu(requested_mtu, overhead);
        log_line(&format!(
            "tunnel: multihop mtu {reduced} ({requested_mtu} - {overhead} B second WireGuard header, floor {MIN_MULTIHOP_MTU})"
        ));
        reduced
    } else {
        requested_mtu
    };
    // The entry device reads whole exit WireGuard packets from the channel, so its MTU is
    // one header larger than the one the exit device exposes to the apps.
    let entry_mtu = exit_peer
        .as_ref()
        .map(|exit| effective_mtu.saturating_add(exit.overhead()));
    if let Some(exit) = exit_peer.as_ref() {
        log_line(&format!("tunnel: multihop exit {}", exit.label()));
    }

    HANDSHAKE.store(false, Ordering::SeqCst);
    RX_BYTES.store(0, Ordering::SeqCst);
    TX_BYTES.store(0, Ordering::SeqCst);
    crate::transports::reset_counters();
    if let Ok(mut guard) = LAST_ERROR.lock() {
        guard.clear();
    }
    log_line(&format!("tunnel: starting to {endpoint}"));

    // Everything that touches the tun or the reactor has to run inside the runtime:
    // `tun::AsyncDevice::new` registers the fd with the reactor and panics without one.
    let outcome = runtime().block_on(async move {
        let Some(socket) = crate::take_relay_socket(&transport_name) else {
            return Err::<_, String>(format!(
                "no relay socket for transport '{transport_name}': the extension must open \
                 and protect one first"
            ));
        };
        let socket = match socket {
            crate::transports::RelaySocket::Udp(std_socket) => {
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
                crate::transports::RelaySocket::Udp(std_socket)
            }
            // udp2tcp: the transport connects this socket itself, after protect(), so
            // there is no UDP socket to probe with and the connect is the reachability
            // test. `bind` logs whether it came up.
            crate::transports::RelaySocket::Tcp(tcp_socket) => {
                log_line("relay socket is TCP: udp2tcp connects it after protect()");
                crate::transports::RelaySocket::Tcp(tcp_socket)
            }
        };

        // The relay's public key is the LWO obfuscation key; the other transports ignore it.
        let transport = TransportFactory::new(
            socket,
            endpoint,
            bridge,
            &transport_name,
            &transport_settings,
            Some(relay_key.to_bytes()),
        )?;
        // LWO v2 asks for timers that match the relay's obfuscation; gotatun can only
        // apply them when the peer is built, below.
        let peer_timers = transport.timer_params();

        let mut config = tun::Configuration::default();
        config.raw_fd(fd).mtu(effective_mtu).close_fd_on_drop(false);
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


        let mut jobs = Vec::new();

        match exit_peer {
            Some(exit) => {
                // Multihop: the entry device faces the real network, the exit device faces
                // the real tun. Between them is a packet channel that carries the exit
                // device's WireGuard datagrams as IP packets for the entry device to
                // encrypt, so no relay sees the client address and the destination at the
                // same time.
                //
                // The entry peer may only route the exit relay: its tun side is the
                // channel, and everything in it is addressed to the exit endpoint.
                let entry_peer = make_peer(
                    relay_key,
                    endpoint,
                    vec![IpNetwork::from(exit.endpoint.ip())],
                    peer_timers,
                );
                let exit_config = make_peer(exit.key, exit.endpoint, allowed_ips, None);
                let exit_key = exit.key;
                let channel_mtu = entry_mtu.unwrap_or(effective_mtu);
                log_line(&format!(
                    "tunnel: multihop mtu {effective_mtu} exposed to apps, {channel_mtu} on the entry channel"
                ));
                log_line(&format!(
                    "tunnel: entry {endpoint}, exit {}",
                    exit.endpoint
                ));

                let (tun_tx, tun_rx, udp_channels) = new_udp_tun_channel(
                    PACKET_CHANNEL_CAPACITY,
                    source_v4,
                    Ipv6Addr::UNSPECIFIED,
                    MtuWatcher::new(channel_mtu),
                );

                let exit_device = Arc::new(
                    DeviceBuilder::new()
                        .with_udp(udp_channels)
                        .with_ip(ObservedTun { inner: tun_device })
                        .with_private_key(StaticSecret::from(secret_bytes))
                        .with_peer(exit_config)
                        .build()
                        .await
                        .map_err(|error| format!("exit device: {error}"))?,
                );

                let entry_device = Arc::new(
                    DeviceBuilder::new()
                        .with_udp(transport)
                        .with_ip_pair(tun_tx, tun_rx)
                        .with_private_key(StaticSecret::from(secret_bytes))
                        .with_peer(entry_peer)
                        .build()
                        .await
                        .map_err(|error| format!("entry device: {error}"))?,
                );

                log_line("tunnel: both devices up, asking for the entry handshake");
                log_line(&format!(
                    "tunnel: entry endpoint {endpoint}, handshake timeout {} s per device",
                    HANDSHAKE_TIMEOUT.as_secs()
                ));

                // The exit handshake can only cross once the entry tunnel is up, so the two
                // are asked in order instead of racing: a packet put into the channel
                // before the entry session exists is dropped, and the exit device would
                // then wait for its own retry timer.
                let handshake_entry = entry_device.clone();
                let handshake_exit = exit_device.clone();
                let entry_key = relay_key;
                jobs.push(tokio::spawn(async move {
                    let entry = tokio::time::timeout(
                        HANDSHAKE_TIMEOUT,
                        handshake_entry.force_handshake(&entry_key),
                    )
                    .await;
                    match entry {
                        Ok(Ok(())) => log_line("tunnel: entry handshake complete"),
                        Ok(Err(error)) => {
                            set_error(format!("entry handshake failed: {error}"));
                            return;
                        }
                        Err(_) => {
                            log_line("tunnel: no entry handshake within 5 s");
                            return;
                        }
                    }
                    let exit = tokio::time::timeout(
                        HANDSHAKE_TIMEOUT,
                        handshake_exit.force_handshake(&exit_key),
                    )
                    .await;
                    match exit {
                        Ok(Ok(())) => log_line("tunnel: exit handshake complete"),
                        Ok(Err(error)) => set_error(format!("exit handshake failed: {error}")),
                        Err(_) => log_line("tunnel: no exit handshake within 5 s"),
                    }
                }));

                let stats_entry = entry_device.clone();
                let stats_exit = exit_device.clone();
                jobs.push(tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(STATS_INTERVAL);
                    loop {
                        ticker.tick().await;
                        let entry = summarize(&stats_entry).await;
                        let exit = summarize(&stats_exit).await;
                        RX_BYTES.store(entry.rx.saturating_add(exit.rx), Ordering::Relaxed);
                        TX_BYTES.store(entry.tx.saturating_add(exit.tx), Ordering::Relaxed);
                        // The chain is only usable when both sessions exist; report the
                        // older of the two, because that one expires first.
                        let age = match (entry.age, exit.age) {
                            (Some(entry_age), Some(exit_age)) => Some(entry_age.max(exit_age)),
                            _ => None,
                        };
                        HANDSHAKE_AGE_MS.store(
                            age.map(|age| age.as_millis() as u64)
                                .unwrap_or(NO_HANDSHAKE_AGE_MS),
                            Ordering::Relaxed,
                        );
                        if entry.sessions > 0
                            && exit.sessions > 0
                            && !HANDSHAKE.swap(true, Ordering::SeqCst)
                        {
                            log_line("tunnel: multihop handshake confirmed on both devices");
                        }
                        maybe_rekey(&stats_entry, &entry_key, entry.age).await;
                        maybe_rekey(&stats_exit, &exit_key, exit.age).await;
                    }
                }));
            }
            None => {
                // Single hop: exactly the device this module built before multihop.
                let relay = make_peer(relay_key, endpoint, allowed_ips, peer_timers);

                let device = Arc::new(
                    DeviceBuilder::new()
                        .with_ip(ObservedTun { inner: tun_device })
                        .with_udp(transport)
                        .with_private_key(StaticSecret::from(secret_bytes))
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

                // Without this nothing is sent until an application happens to generate
                // traffic, so an idle tunnel would never handshake and the UI would never
                // leave "connecting".
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
                        // The poller below still notices a late handshake; this only ends
                        // the wait.
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
                            // Only the tick that crosses the threshold asks, so a failing
                            // relay is retried by the handshake task rather than flooded
                            // from here.
                            let _ = stats_device.force_handshake(&relay_key).await;
                        }
                        HANDSHAKE_AGE_MS.store(age_ms, Ordering::Relaxed);
                        if handshake && !HANDSHAKE.swap(true, Ordering::SeqCst) {
                            log_line("tunnel: handshake confirmed by peer stats");
                        }
                    }
                }));
            }
        }

        MULTIHOP.store(multihop, Ordering::SeqCst);
        EFFECTIVE_MTU.store(effective_mtu as u64, Ordering::SeqCst);

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
                &json!({
                    "ok": true,
                    "endpoint": endpoint.to_string(),
                    "multihop": multihop,
                    "mtu": effective_mtu,
                })
                .to_string(),
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
    MULTIHOP.store(false, Ordering::SeqCst);
    EFFECTIVE_MTU.store(0, Ordering::SeqCst);
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
        "udpSent": crate::transports::counters().0,
        "udpRecv": crate::transports::counters().1,
        "inbound": HANDSHAKE.load(Ordering::SeqCst),
        "rxBytes": RX_BYTES.load(Ordering::Relaxed),
        "txBytes": TX_BYTES.load(Ordering::Relaxed),
        "handshakeAgeMs": HANDSHAKE_AGE_MS.load(Ordering::Relaxed),
        "multihop": MULTIHOP.load(Ordering::SeqCst),
        "mtu": EFFECTIVE_MTU.load(Ordering::SeqCst),
        "error": error,
    });
    write_out(out, capacity, &payload.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A syntactically valid 32-byte WireGuard key, enough for parsing tests.
    fn exit_key() -> String {
        base64::engine::general_purpose::STANDARD.encode([7u8; 32])
    }

    #[test]
    fn multihop_mtu_pays_for_the_second_header() {
        assert_eq!(multihop_mtu(1420, 60), 1360);
        assert_eq!(multihop_mtu(1420, 80), 1340);
    }

    #[test]
    fn multihop_mtu_never_goes_below_the_ipv6_floor() {
        assert_eq!(multihop_mtu(1300, 60), 1280);
        assert_eq!(multihop_mtu(1280, 80), 1280);
    }

    #[test]
    fn empty_settings_are_a_single_hop() {
        let settings = parse_settings("").expect("empty settings parse");
        assert!(resolve_exit(&settings).expect("no exit").is_none());
    }

    #[test]
    fn settings_carry_the_exit_peer_and_source_address() {
        let raw = format!(
            r#"{{"exit":{{"ip":"185.65.134.1","publicKey":"{}","port":51820,"hostname":"se-sto-wg-001"}},"sourceIpv4":"10.170.64.72/32"}}"#,
            exit_key()
        );
        let settings = parse_settings(&raw).expect("settings parse");
        assert_eq!(
            parse_source_v4(&settings.source_ipv4),
            Ipv4Addr::new(10, 170, 64, 72)
        );
        let exit = resolve_exit(&settings).expect("exit parse").expect("some exit");
        assert_eq!(exit.endpoint, "185.65.134.1:51820".parse().expect("addr"));
        assert_eq!(exit.hostname, "se-sto-wg-001");
        // The exit is reached over IPv4: 20 (IP) + 8 (UDP) + 32 (WireGuard data+tag).
        assert_eq!(exit.overhead(), 60);
    }

    #[test]
    fn exit_port_defaults_to_the_multihop_port() {
        let raw = format!(
            r#"{{"exit":{{"ip":"185.65.134.1","publicKey":"{}"}}}}"#,
            exit_key()
        );
        let settings = parse_settings(&raw).expect("settings parse");
        let exit = resolve_exit(&settings).expect("exit parse").expect("some exit");
        assert_eq!(exit.endpoint.port(), 51820);
    }

    #[test]
    fn a_broken_exit_is_an_error_not_a_silent_single_hop() {
        let raw = format!(
            r#"{{"exit":{{"ip":"not-an-ip","publicKey":"{}","port":51820}}}}"#,
            exit_key()
        );
        let settings = parse_settings(&raw).expect("settings parse");
        assert!(resolve_exit(&settings).is_err());
    }

    #[test]
    fn unknown_transport_keys_do_not_break_the_exit() {
        // Transport units add their own keys next to `exit`; the core must ignore them.
        let raw = format!(
            r#"{{"exit":{{"ip":"185.65.134.1","publicKey":"{}","port":51820}},"lwo":"v2","udp2tcp":4433}}"#,
            exit_key()
        );
        let settings = parse_settings(&raw).expect("settings parse");
        assert!(resolve_exit(&settings).expect("exit parse").is_some());
    }
}
