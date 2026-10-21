//! WireGuard datagrams inside MASQUE CONNECT-UDP over QUIC.
//!
//! A filtered network can drop WireGuard and Shadowsocks alike while still passing QUIC on
//! UDP 443, because blocking that port breaks too much of the web. Mullvad relays that
//! advertise `features.quic` run a MASQUE proxy on that port: the client opens a QUIC
//! connection to it, sends one HTTP/3 extended CONNECT (CONNECT-UDP) naming the relay's
//! WireGuard listener as the target, and then carries every WireGuard datagram as an HTTP
//! datagram on that request, with a per-relay token in the CONNECT request.
//!
//! The protocol lives in [`mullvad_masque_proxy`], vendored from the upstream client: it
//! owns the QUIC and HTTP/3 stacks, the CONNECT exchange, the datagram framing and the
//! fragmentation needed when the path MTU is smaller than the tunnel MTU. This module only
//! adapts it to the [`Transport`] contract: it hands the already-protected socket to the
//! client, pumps WireGuard datagrams through a pair of channels, and reports the MTU
//! overhead the QUIC framing adds.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use gotatun::packet::{Packet, PacketBufPool};
use mullvad_masque_proxy::client::{Client, ClientConfig};
use mullvad_masque_proxy::MAX_INFLIGHT_PACKETS;
use serde_json::Value;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::{
    count_recv, count_sent, log_datagram, DatagramRecv, DatagramSend, RecvPipe, SendPipe, Transport,
};
use crate::log_line;

/// UDP port of the MASQUE proxy. It presents itself as an ordinary HTTPS server, so it is
/// 443, not one of the WireGuard ports.
const PROXY_PORT: u16 = 443;

/// WireGuard endpoint the proxy forwards the datagrams to.
///
/// As with Shadowsocks, the proxy runs on the relay and its CONNECT-UDP target is the
/// relay's own loopback listener; this is what the upstream client sends
/// (`talpid-wireguard/src/obfuscation.rs`), not the address the engine dialled.
const INNER_WIREGUARD: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51820);

/// Path MTU the QUIC client is sized for, IP header included.
///
/// This is the link MTU, not the tunnel MTU: the client subtracts the IP and UDP headers
/// and sizes QUIC datagrams to what is left, fragmenting a WireGuard datagram only when it
/// no longer fits. 1500 is what the upstream client passes (its `obfuscation_mtu` is the
/// route MTU).
const PATH_MTU: u16 = 1500;

/// Bytes QUIC and MASQUE add to every WireGuard datagram on the wire.
///
/// The conservative QUIC header figure the proxy itself uses (41 bytes: flags, connection
/// ID, packet number and AEAD tag), plus the DATAGRAM frame header (4: type, length, stream
/// ID) and the HTTP datagram context ID (1). A datagram too large for one QUIC packet is
/// split by the proxy client, and each fragment adds a 5-byte fragment header; at the
/// tunnel's 1420-byte MTU that happens for full-size packets, because QUIC's own framing
/// leaves about 1416 bytes of the 1500-byte path.
const MTU_OVERHEAD: u16 = 41 + 4 + 1;

/// How long the QUIC handshake and the CONNECT-UDP exchange get before the ladder moves to
/// the next attempt. The extension gives an attempt five seconds overall.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// What the extension knows about this relay's proxy, from `features.quic`.
#[derive(Debug)]
struct Settings {
    /// Hostname the proxy's certificate is issued for; the TLS SNI and HTTP authority.
    domain: String,
    /// Per-relay authorization token for the CONNECT request, without the "Bearer " prefix.
    token: String,
    /// Proxy address in the family this attempt dials.
    addr: IpAddr,
}

impl Settings {
    /// Parses `{"domain": "...", "token": "...", "addr": "<ip>"}`.
    ///
    /// The extension picks the address matching the ladder entry's family, so whatever is
    /// here is what this attempt must dial. A missing field is an error rather than a
    /// silent fallback: a QUIC attempt without a token cannot authenticate.
    fn parse(settings: &str) -> Result<Self, String> {
        if settings.trim().is_empty() {
            return Err("quic transport needs settings {\"domain\",\"token\",\"addr\"}".into());
        }
        let value: Value = serde_json::from_str(settings)
            .map_err(|error| format!("quic settings are not valid JSON: {error}"))?;
        let text = |key: &str| -> Result<String, String> {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| format!("quic settings: missing \"{key}\""))
        };

        let domain = text("domain")?;
        let token = text("token")?;
        // Upstream rejects a prefixed token: the client adds "Bearer " itself, and a
        // doubled prefix fails authentication in a way that looks like a dead proxy.
        if token.starts_with("Bearer") {
            return Err("quic settings: token must not start with \"Bearer\"".into());
        }
        let addr_text = text("addr")?;
        let addr: IpAddr = addr_text.parse().map_err(|error| {
            format!("quic settings: \"{addr_text}\" is not an IP address: {error}")
        })?;
        Ok(Self {
            domain,
            token,
            addr,
        })
    }
}

/// A MASQUE proxy the extension chose for this attempt.
pub struct Quic {
    socket: Option<UdpSocket>,
    /// The endpoint the engine believes it is talking to. It is what received datagrams
    /// are reported from, so the peer's address never looks like it roamed.
    relay: SocketAddr,
    settings: Settings,
}

impl Quic {
    /// `settings` is the extension's JSON; it is validated here so a misconfigured ladder
    /// entry fails the attempt synchronously instead of when the first packet is sent.
    pub fn new(socket: UdpSocket, relay: SocketAddr, settings: &str) -> Result<Self, String> {
        Ok(Self {
            socket: Some(socket),
            relay,
            settings: Settings::parse(settings)?,
        })
    }
}

impl Transport for Quic {
    fn bind<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<(SendPipe, RecvPipe)>> + Send + 'a>> {
        Box::pin(async move {
            let socket = self
                .socket
                .take()
                .ok_or_else(|| io::Error::other("quic: transport already bound"))?;
            let proxy = SocketAddr::new(self.settings.addr, PROXY_PORT);
            let domain = self.settings.domain.clone();

            // The QUIC client takes ownership of the protected socket, so its datagrams
            // bypass the tunnel the engine is about to build.
            let config = ClientConfig::builder()
                .quinn_socket(socket)
                .server_addr(proxy)
                .server_host(domain.clone())
                .target_addr(INNER_WIREGUARD)
                .auth_header(Some(format!("Bearer {}", self.settings.token)))
                .mtu(PATH_MTU)
                .build();

            log_line(&format!(
                "quic: connecting to {proxy} (sni {domain}, target {INNER_WIREGUARD})"
            ));
            // Connecting here, inside bind, is what turns a dead proxy or a rejected token
            // into a failed attempt the ladder can skip. Spawning it would leave the engine
            // running against a pipe that never opens.
            let client = tokio::time::timeout(CONNECT_TIMEOUT, Client::connect(config))
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "quic: no MASQUE session with {proxy} after {} s",
                            CONNECT_TIMEOUT.as_secs()
                        ),
                    )
                })?
                .map_err(|error| {
                    // The Display of the client error is one line; the debug form keeps the
                    // QUIC or HTTP/3 cause in the diagnostics log.
                    log_line(&format!("quic: connect to {proxy} failed: {error:?}"));
                    io::Error::other(format!("quic: {error}"))
                })?;
            log_line(&format!("quic: MASQUE session to {proxy} established"));

            let (outgoing_tx, outgoing_rx) = mpsc::channel::<BytesMut>(MAX_INFLIGHT_PACKETS);
            let (incoming_tx, incoming_rx) = mpsc::channel::<BytesMut>(MAX_INFLIGHT_PACKETS);
            let running = client.proxy_channels(outgoing_rx, incoming_tx);
            // The proxy client never returns on its own while the connection is healthy, and
            // it owns the connection's tasks. Keeping this handle shared by both pipes means
            // the session dies with the last of them, when the device is torn down.
            let task = tokio::spawn(async move {
                match running.until_closed().await {
                    Ok(()) => log_line("quic: MASQUE session closed by the proxy"),
                    Err(error) => log_line(&format!("quic: MASQUE session ended: {error:?}")),
                }
            });
            let client = Arc::new(ClientGuard(task));

            let send: SendPipe = Box::new(QuicSend {
                outgoing: outgoing_tx,
                relay: self.relay,
                _client: Arc::clone(&client),
            });
            let recv: RecvPipe = Box::new(QuicRecv {
                incoming: incoming_rx,
                relay: self.relay,
                _client: client,
            });
            Ok((send, recv))
        })
    }

    fn mtu_overhead(&self) -> u16 {
        MTU_OVERHEAD
    }

    fn name(&self) -> &'static str {
        "quic"
    }
}

/// Stops the proxy client when the last pipe that could use it is dropped.
///
/// Aborting the task drops the [`mullvad_masque_proxy::client::RunningClient`] it owns,
/// which closes the QUIC connection and every task behind it.
struct ClientGuard(JoinHandle<()>);

impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone)]
struct QuicSend {
    outgoing: mpsc::Sender<BytesMut>,
    relay: SocketAddr,
    /// Keeps the proxy session alive while the engine holds the send half.
    _client: Arc<ClientGuard>,
}

struct QuicRecv {
    incoming: mpsc::Receiver<BytesMut>,
    relay: SocketAddr,
    /// Keeps the proxy session alive while the engine holds the receive half.
    _client: Arc<ClientGuard>,
}

impl DatagramSend for QuicSend {
    fn send<'a>(
        &'a self,
        packet: Packet,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            // The proxy client does the framing (context ID, fragmentation, QUIC DATAGRAM
            // frames); this layer only moves the WireGuard datagram into its channel.
            let datagram = BytesMut::from(packet.as_ref());
            self.outgoing.send(datagram).await.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "quic: MASQUE session closed")
            })?;
            let count = count_sent();
            log_datagram("out", self.relay, packet.as_ref(), count);
            Ok(())
        })
    }
}

impl DatagramRecv for QuicRecv {
    fn recv<'a>(
        &'a mut self,
        _pool: &'a mut PacketBufPool,
    ) -> Pin<Box<dyn Future<Output = io::Result<(Packet, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move {
            let datagram = self.incoming.recv().await.ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "quic: MASQUE session closed")
            })?;
            let count = count_recv();
            log_datagram("in", self.relay, &datagram, count);
            Ok((Packet::from_bytes(datagram), self.relay))
        })
    }
}
