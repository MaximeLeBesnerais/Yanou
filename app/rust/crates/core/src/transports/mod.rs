//! How WireGuard datagrams reach a relay.
//!
//! One module per transport, each implementing [`Transport`]: `direct` is plain UDP to the
//! relay, `shadowsocks` wraps every datagram for a bridge relay, `quic` carries them as
//! MASQUE CONNECT-UDP datagrams through a QUIC proxy on the relay. LWO and udp2tcp land
//! here as sibling modules and plug into [`TransportFactory`], without touching the engine.
//!
//! The socket is created by the extension and `protect()`ed, so it bypasses the tunnel the
//! engine is building.

mod direct;
mod quic;
mod shadowsocks;

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use gotatun::packet::{Packet, PacketBufPool};
use gotatun::udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams};
use tokio::net::UdpSocket;

/// A datagram pipe that has already been configured for one relay.
///
/// A transport implements these two traits for the pipe it hands to the engine; the boxed
/// futures keep the factory able to choose a transport at runtime without an enum listing
/// every implementation.
pub trait DatagramSend: Send + Sync {
    fn send<'a>(
        &'a self,
        packet: Packet,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

/// The receiving half of a transport's datagram pipe.
pub trait DatagramRecv: Send + Sync {
    fn recv<'a>(
        &'a mut self,
        pool: &'a mut PacketBufPool,
    ) -> Pin<Box<dyn Future<Output = io::Result<(Packet, SocketAddr)>> + Send + 'a>>;
}

pub type SendPipe = Box<dyn DatagramSend>;
pub type RecvPipe = Box<dyn DatagramRecv>;

/// One way of moving WireGuard datagrams to a relay.
///
/// A transport is created from the protected socket and the relay endpoint, and `bind`
/// returns the send/recv pair the engine drives. `bind` is asynchronous because a
/// transport may have to establish something first (a TCP stream for udp2tcp, a QUIC
/// connection for MASQUE) before it can carry a datagram. `mtu_overhead` is what the
/// transport adds to every datagram, for the MTU accounting a later unit does; it is not
/// applied yet.
pub trait Transport: Send + Sync + 'static {
    fn bind<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<(SendPipe, RecvPipe)>> + Send + 'a>>;
    /// Bytes this transport adds to each WireGuard datagram.
    #[allow(dead_code)]
    fn mtu_overhead(&self) -> u16;
    /// Transport name, for logs and the connection details a later unit adds.
    #[allow(dead_code)]
    fn name(&self) -> &'static str;
}

static UDP_SENT: AtomicU64 = AtomicU64::new(0);
static UDP_RECV: AtomicU64 = AtomicU64::new(0);

pub fn reset_counters() {
    UDP_SENT.store(0, Ordering::SeqCst);
    UDP_RECV.store(0, Ordering::SeqCst);
}

pub fn counters() -> (u64, u64) {
    (UDP_SENT.load(Ordering::Relaxed), UDP_RECV.load(Ordering::Relaxed))
}

/// Counts one datagram this side sent, returning its 1-based sequence number.
fn count_sent() -> u64 {
    UDP_SENT.fetch_add(1, Ordering::Relaxed) + 1
}

/// Counts one datagram this side received, returning its 1-based sequence number.
fn count_recv() -> u64 {
    UDP_RECV.fetch_add(1, Ordering::Relaxed) + 1
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

/// Picks the transport for this connection and adapts it to the engine's UDP traits.
pub struct TransportFactory {
    transport: Box<dyn Transport>,
}

impl TransportFactory {
    /// `transport` names the transport to build; `bridge` is the Shadowsocks endpoint it
    /// needs. Adding a transport is one arm here and one module, never a new selector.
    pub fn new(
        socket: UdpSocket,
        relay: SocketAddr,
        bridge: Option<SocketAddr>,
        transport: &str,
        settings: &str,
    ) -> Result<Self, String> {
        let transport: Box<dyn Transport> = match transport {
            "" | "direct" => Box::new(direct::Direct::new(socket, relay)),
            "shadowsocks" => match bridge {
                Some(bridge) => Box::new(shadowsocks::Shadowsocks::new(socket, relay, bridge)?),
                None => return Err("shadowsocks without a bridge endpoint".into()),
            },
            "quic" => Box::new(quic::Quic::new(socket, relay, settings)?),
            other => return Err(format!("unknown transport '{other}'")),
        };
        Ok(Self { transport })
    }
}

impl UdpTransportFactory for TransportFactory {
    type Send = TransportSend;
    type Recv = TransportRecv;

    async fn bind(
        &mut self,
        _params: &UdpTransportFactoryParams,
    ) -> io::Result<(Self::Send, Self::Recv)> {
        let (send, recv) = self.transport.bind().await?;
        let inner: Arc<dyn DatagramSend> = Arc::from(send);
        Ok((TransportSend { inner }, TransportRecv { inner: recv }))
    }
}

#[derive(Clone)]
pub struct TransportSend {
    inner: Arc<dyn DatagramSend>,
}

pub struct TransportRecv {
    inner: RecvPipe,
}

impl UdpSend for TransportSend {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, _destination: SocketAddr) -> io::Result<()> {
        self.inner.send(packet).await
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }
}

impl UdpRecv for TransportRecv {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        self.inner.recv(pool).await
    }
}
