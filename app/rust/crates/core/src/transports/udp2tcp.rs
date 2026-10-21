//! udp2tcp: WireGuard datagrams carried inside a TCP stream to the relay.
//!
//! Filters that drop UDP but still pass TCP are common enough that Mullvad ships this as
//! a full obfuscation mode. The relay listens on TCP 80, 443 and 5001 for it (the official
//! client hardcodes that list; the API does not publish it), and the stream carries one
//! datagram per length-prefixed frame: a big-endian `u16` length followed by the datagram.
//! That framing is `udp-over-tcp`'s, and so is the forwarder that owns the stream; this
//! module only connects the forwarder's in-memory queues to the engine's datagram pipe.
//!
//! Upstream reference: `tunnel-obfuscation/src/udp2tcp.rs` in the Mullvad client.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use gotatun::packet::{Packet, PacketBufPool};
use serde_json::Value;
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{mpsc, Mutex};
use udp_over_tcp::{process_udp_over_tcp, DatagramSocket, HEADER_LEN};

use super::{
    count_recv, count_sent, log_datagram, DatagramRecv, DatagramSend, RecvPipe, SendPipe,
    Transport,
};

/// How many datagrams may wait in either direction before the engine blocks on send.
const DATAGRAM_QUEUE_LEN: usize = 128;

/// A TCP connect that hangs must not outlive one rung of the ladder. The extension gives
/// each attempt 5 s and `mh_tunnel_start` is a blocking call, so waiting for the OS
/// connect timeout (over a minute on a filtered network) would freeze the ladder on a
/// port that is being dropped.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// The relay port used when the extension sends no usable `{"port":n}` setting. 443 is
/// the one of the three udp2tcp ports a filtered network is least likely to drop.
const DEFAULT_PORT: u16 = 443;

/// The transport itself, before it is bound.
///
/// It holds the *unconnected* TCP socket the extension opened and protected, exactly like
/// `Direct` holds the UDP one. The socket is a `TcpSocket` rather than a `TcpStream`
/// because connecting here, before `protect()` ran, would bind the connection to the
/// network route that is about to become the tunnel.
pub struct Udp2Tcp {
    socket: Option<TcpSocket>,
    /// Where the stream is opened: the relay's address and the udp2tcp port.
    peer: SocketAddr,
    /// The relay's WireGuard endpoint. The engine ignores it when sending through an
    /// obfuscated transport, but it is what received datagrams are reported as coming
    /// from, and it is what diagnostics show.
    relay: SocketAddr,
}

impl Udp2Tcp {
    /// `settings` is the JSON the extension builds for this transport: `{"port":443}`.
    /// A missing or malformed setting falls back to [`DEFAULT_PORT`] with a log line
    /// instead of failing the attempt, because the three ports are interchangeable.
    pub fn new(socket: TcpSocket, relay: SocketAddr, settings: &str) -> Result<Self, String> {
        let port = match configured_port(settings) {
            Some(port) => port,
            None => {
                crate::log_line(&format!(
                    "udp2tcp: no usable port in settings {settings:?}, using {DEFAULT_PORT}"
                ));
                DEFAULT_PORT
            }
        };
        Ok(Self {
            socket: Some(socket),
            peer: SocketAddr::new(relay.ip(), port),
            relay,
        })
    }
}

/// Reads `{"port":n}` from the extension's per-transport settings.
fn configured_port(settings: &str) -> Option<u16> {
    serde_json::from_str::<Value>(settings)
        .ok()?
        .get("port")?
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
}

impl Transport for Udp2Tcp {
    fn bind<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<(SendPipe, RecvPipe)>> + Send + 'a>> {
        Box::pin(async move {
            let socket = self
                .socket
                .take()
                .ok_or_else(|| io::Error::other("udp2tcp is already bound"))?;
            let peer = self.peer;

            // The socket is already protected: this connect goes out on the underlying
            // network, not into the tunnel that is being built.
            let stream = match tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(peer)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!("udp2tcp connect {peer}: {error}"),
                    ))
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("udp2tcp connect {peer} timed out"),
                    ))
                }
            };
            // Length-prefixed datagrams are small and latency matters more than packing.
            stream.set_nodelay(true)?;
            let local = stream.local_addr().ok();
            crate::log_line(&format!(
                "udp2tcp: tcp stream to {peer} up (local {})",
                local.map(|addr| addr.to_string()).unwrap_or_else(|| "?".into())
            ));

            let (outgoing_tx, outgoing_rx) = mpsc::channel(DATAGRAM_QUEUE_LEN);
            let (incoming_tx, incoming_rx) = mpsc::channel(DATAGRAM_QUEUE_LEN);
            let queues = Queues {
                incoming: incoming_tx,
                outgoing: Mutex::new(outgoing_rx),
            };
            let forwarder = Arc::new(Forwarder(tokio::spawn(forward(queues, stream, peer))));

            let send: SendPipe = Box::new(Udp2TcpSend {
                outgoing: outgoing_tx,
                peer,
                local,
                _forwarder: Arc::clone(&forwarder),
            });
            let recv: RecvPipe = Box::new(Udp2TcpRecv {
                incoming: Mutex::new(incoming_rx),
                relay: self.relay,
                _forwarder: forwarder,
            });
            Ok((send, recv))
        })
    }

    fn mtu_overhead(&self) -> u16 {
        // The length header, plus a maximum-size TCP header where the datagram would
        // otherwise have had an 8-byte UDP header. Same accounting as upstream.
        let max_tcp_header_len = 60;
        let udp_header_len = 8;
        u16::try_from(max_tcp_header_len - udp_header_len + HEADER_LEN).unwrap_or(u16::MAX)
    }

    fn name(&self) -> &'static str {
        "udp2tcp"
    }
}

/// Runs the framing forwarder until either direction stops.
async fn forward(queues: Queues, stream: TcpStream, peer: SocketAddr) {
    process_udp_over_tcp(queues, stream, None).await;
    crate::log_line(&format!("udp2tcp: stream to {peer} closed"));
}

/// Aborts the forwarder once both halves of the pipe are gone, instead of leaving a task
/// and its stream behind when the device is dropped.
struct Forwarder(tokio::task::JoinHandle<()>);

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The sending half of the pipe: hands datagrams to the forwarder's outgoing queue.
struct Udp2TcpSend {
    outgoing: mpsc::Sender<Box<[u8]>>,
    /// Logged as the destination of each datagram, like the other transports do.
    peer: SocketAddr,
    local: Option<SocketAddr>,
    _forwarder: Arc<Forwarder>,
}

impl DatagramSend for Udp2TcpSend {
    fn send<'a>(
        &'a self,
        packet: Packet,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.outgoing
                .send(Box::from(packet.as_ref()))
                .await
                .map_err(|_| stopped())?;
            let count = count_sent();
            log_datagram("out", self.peer, packet.as_ref(), count);
            Ok(())
        })
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.local)
    }
}

/// The receiving half: takes datagrams the forwarder decoded from the stream.
struct Udp2TcpRecv {
    incoming: Mutex<mpsc::Receiver<Box<[u8]>>>,
    relay: SocketAddr,
    _forwarder: Arc<Forwarder>,
}

impl DatagramRecv for Udp2TcpRecv {
    fn recv<'a>(
        &'a mut self,
        pool: &'a mut PacketBufPool,
    ) -> Pin<Box<dyn Future<Output = io::Result<(Packet, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move {
            let datagram = self
                .incoming
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(stopped)?;
            let mut packet = pool.get();
            {
                let buffer: &mut [u8] = packet.buf_mut();
                if datagram.len() > buffer.len() {
                    return Err(io::Error::other(format!(
                        "udp2tcp datagram ({} B) does not fit the packet buffer ({} B)",
                        datagram.len(),
                        buffer.len()
                    )));
                }
                buffer[..datagram.len()].copy_from_slice(&datagram);
            }
            packet.truncate(datagram.len());
            let count = count_recv();
            log_datagram("in", self.relay, packet.as_ref(), count);
            Ok((packet, self.relay))
        })
    }
}

/// The forwarder's end of the two queues.
///
/// `udp-over-tcp` normally reads and writes a real UDP socket; this stands in for one so
/// the datagrams stay in memory. `send` here means "a datagram arrived from the relay",
/// which is why it fills the queue the engine receives from.
struct Queues {
    incoming: mpsc::Sender<Box<[u8]>>,
    outgoing: Mutex<mpsc::Receiver<Box<[u8]>>>,
}

impl DatagramSocket for Queues {
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.incoming
            .send(Box::from(buf))
            .await
            .map_err(|_| stopped())?;
        Ok(buf.len())
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let datagram = self
            .outgoing
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(stopped)?;
        let target = buf
            .get_mut(..datagram.len())
            .ok_or_else(|| io::Error::other("datagram does not fit the receive buffer"))?;
        target.copy_from_slice(&datagram);
        Ok(datagram.len())
    }
}

/// The forwarder is gone: fail sends and receives instead of waiting on a dead stream.
fn stopped() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "the udp-over-tcp forwarder stopped",
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use bytes::BytesMut;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// One datagram in each direction must appear on the wire with the length header the
    /// protocol prescribes, and decode back to the same bytes.
    #[tokio::test]
    async fn length_prefixed_framing_in_both_directions() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let socket = TcpSocket::new_v4().unwrap();
        socket.bind(loopback(0)).unwrap();
        // The WireGuard endpoint is irrelevant on the TCP side; only the port setting
        // decides where the stream goes.
        let mut transport =
            Udp2Tcp::new(socket, loopback(51820), &format!("{{\"port\":{port}}}")).unwrap();
        let (send, mut recv) = transport.bind().await.unwrap();
        let (mut remote, _) = listener.accept().await.unwrap();

        send.send(Packet::from_bytes(BytesMut::from(&[1u8, 2, 3][..])))
            .await
            .unwrap();
        let mut framed = [0u8; 5];
        remote.read_exact(&mut framed).await.unwrap();
        assert_eq!(framed, [0, 3, 1, 2, 3]);

        remote.write_all(&[0, 2, 9, 8]).await.unwrap();
        let mut pool = PacketBufPool::new(1);
        let (packet, source) = recv.recv(&mut pool).await.unwrap();
        assert_eq!(packet.as_ref(), &[9u8, 8]);
        assert_eq!(source, loopback(51820));
    }

    #[test]
    fn port_comes_from_settings_and_falls_back_to_443() {
        assert_eq!(configured_port("{\"port\":5001}"), Some(5001));
        assert_eq!(configured_port(""), None);
    }
}
