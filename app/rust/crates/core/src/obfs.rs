//! The WireGuard transport: plain UDP, or Mullvad's Shadowsocks bridge when plain UDP is
//! dropped.
//!
//! On a filtered network the relay IPs are unreachable — the handshake initiation leaves
//! the device and nothing comes back, on every port. Mullvad's own answer, and the reason
//! the bridge relay list exists, is to reach a bridge instead and let it forward the
//! WireGuard datagrams. That is what `shadowsocks` here does: AEAD-encrypted UDP packets
//! to the bridge, each carrying the WireGuard endpoint as its destination address.
//!
//! The socket is created by the extension and `protect()`ed, so it bypasses the tunnel the
//! engine is building.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use gotatun::packet::{Packet, PacketBufPool};
use gotatun::udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams};
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::udprelay::proxy_socket::{ProxySocket, UdpSocketType};
use shadowsocks::relay::Address;
use tokio::net::UdpSocket;

/// The bridge relays only speak this one cipher, with a published password: the
/// obfuscation is not a secret, the WireGuard layer inside it is.
pub const BRIDGE_CIPHER: CipherKind = CipherKind::AES_256_GCM;
pub const BRIDGE_PASSWORD: &str = "mullvad";

/// Inside the Shadowsocks tunnel the WireGuard endpoint is the relay's own loopback
/// listener, not its public address. See `talpid-wireguard/src/obfuscation.rs`.
fn shadowsocks_inner() -> SocketAddr {
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 51820)
}

type Proxy = ProxySocket<shadowsocks::net::UdpSocket>;

static UDP_SENT: AtomicU64 = AtomicU64::new(0);
static UDP_RECV: AtomicU64 = AtomicU64::new(0);

pub fn reset_counters() {
    UDP_SENT.store(0, Ordering::SeqCst);
    UDP_RECV.store(0, Ordering::SeqCst);
}

pub fn counters() -> (u64, u64) {
    (UDP_SENT.load(Ordering::Relaxed), UDP_RECV.load(Ordering::Relaxed))
}

fn packet_kind(first: u8) -> &'static str {
    match first {
        1 => "handshake-init",
        2 => "handshake-response",
        3 => "cookie-reply",
        4 => "data",
        _ => "unexpected",
    }
}

/// First few datagrams per direction, then every 64th: enough to see whether the relay
/// answers, quiet once real traffic flows.
fn log_datagram(direction: &str, peer: SocketAddr, bytes: &[u8], count: u64) {
    if count > 8 && count % 64 != 0 {
        return;
    }
    let kind = bytes.first().map(|first| packet_kind(*first)).unwrap_or("empty");
    crate::log_line(&format!(
        "udp {direction} {peer} {} B {kind} (#{count})",
        bytes.len()
    ));
}

#[derive(Clone)]
enum Mode {
    Direct(Arc<UdpSocket>),
    Bridge { proxy: Arc<Proxy>, bridge: SocketAddr },
}

#[derive(Clone)]
pub struct TransportSend {
    mode: Mode,
    relay: SocketAddr,
}

pub struct TransportRecv {
    mode: Mode,
    relay: SocketAddr,
    /// `ProxySocket::recv_from` decrypts in place, so it needs a full-size buffer.
    buffer: Vec<u8>,
}

pub struct TransportFactory {
    mode: Mode,
    relay: SocketAddr,
}

impl TransportFactory {
    pub fn new(
        socket: UdpSocket,
        relay: SocketAddr,
        bridge: Option<SocketAddr>,
    ) -> Result<Self, String> {
        let mode = match bridge {
            None => Mode::Direct(Arc::new(socket)),
            Some(bridge) => {
                let context = Context::new_shared(ServerType::Local);
                let config = ServerConfig::new(bridge, BRIDGE_PASSWORD, BRIDGE_CIPHER)
                    .map_err(|error| format!("bridge config: {error}"))?;
                let proxy = ProxySocket::from_socket(
                    UdpSocketType::Client,
                    context,
                    &config,
                    shadowsocks::net::UdpSocket::from(socket),
                );
                Mode::Bridge {
                    proxy: Arc::new(proxy),
                    bridge,
                }
            }
        };
        Ok(Self { mode, relay })
    }
}

impl UdpTransportFactory for TransportFactory {
    type Send = TransportSend;
    type Recv = TransportRecv;

    async fn bind(
        &mut self,
        _params: &UdpTransportFactoryParams,
    ) -> io::Result<(Self::Send, Self::Recv)> {
        Ok((
            TransportSend {
                mode: self.mode.clone(),
                relay: self.relay,
            },
            TransportRecv {
                mode: self.mode.clone(),
                relay: self.relay,
                buffer: vec![0u8; 65_536],
            },
        ))
    }
}

impl UdpSend for TransportSend {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, _destination: SocketAddr) -> io::Result<()> {
        match &self.mode {
            Mode::Direct(socket) => {
                socket.send_to(packet.as_ref(), self.relay).await?;
            }
            Mode::Bridge { proxy, bridge } => {
                proxy
                    .send_to(*bridge, &Address::SocketAddress(shadowsocks_inner()), packet.as_ref())
                    .await
                    .map_err(io::Error::other)?;
            }
        }
        let count = UDP_SENT.fetch_add(1, Ordering::Relaxed) + 1;
        log_datagram("out", self.relay, packet.as_ref(), count);
        Ok(())
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        match &self.mode {
            Mode::Direct(socket) => socket.local_addr().map(Some),
            Mode::Bridge { .. } => Ok(None),
        }
    }
}

impl UdpRecv for TransportRecv {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        match &self.mode {
            Mode::Direct(socket) => {
                let mut packet = pool.get();
                let (length, source) = {
                    let buffer: &mut [u8] = packet.buf_mut();
                    socket.recv_from(buffer).await?
                };
                packet.truncate(length);
                let count = UDP_RECV.fetch_add(1, Ordering::Relaxed) + 1;
                log_datagram("in", source, packet.as_ref(), count);
                Ok((packet, source))
            }
            Mode::Bridge { proxy, .. } => {
                let (length, _from, destination, _control) = proxy
                    .recv_from(&mut self.buffer)
                    .await
                    .map_err(io::Error::other)?;
                let packet = Packet::from_bytes(bytes::BytesMut::from(&self.buffer[..length]));
                let count = UDP_RECV.fetch_add(1, Ordering::Relaxed) + 1;
                log_datagram("in", self.relay, packet.as_ref(), count);
                Ok((packet, self.relay))
            }
        }
    }
}
