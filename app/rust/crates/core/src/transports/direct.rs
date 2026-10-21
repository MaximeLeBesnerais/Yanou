//! Plain WireGuard over UDP.
//!
//! The engine's datagrams are sent to the relay's own address, with no wrapper. This is the
//! path every network that does not filter WireGuard uses, and the IPv6 variant is the one
//! that survives a filtered IPv4 network.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use gotatun::packet::{Packet, PacketBufPool};
use tokio::net::UdpSocket;

use super::{
    count_recv, count_sent, log_datagram, DatagramRecv, DatagramSend, RecvPipe, SendPipe,
    Transport,
};

pub struct Direct {
    socket: Arc<UdpSocket>,
    relay: SocketAddr,
}

impl Direct {
    pub fn new(socket: UdpSocket, relay: SocketAddr) -> Self {
        Self {
            socket: Arc::new(socket),
            relay,
        }
    }
}

impl Transport for Direct {
    fn bind<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<(SendPipe, RecvPipe)>> + Send + 'a>> {
        Box::pin(async move {
            let send: SendPipe = Box::new(DirectSend {
                socket: Arc::clone(&self.socket),
                relay: self.relay,
            });
            let recv: RecvPipe = Box::new(DirectRecv {
                socket: Arc::clone(&self.socket),
            });
            Ok((send, recv))
        })
    }

    fn mtu_overhead(&self) -> u16 {
        0
    }

    fn name(&self) -> &'static str {
        "direct"
    }
}

#[derive(Clone)]
struct DirectSend {
    socket: Arc<UdpSocket>,
    relay: SocketAddr,
}

struct DirectRecv {
    socket: Arc<UdpSocket>,
}

impl DatagramSend for DirectSend {
    fn send<'a>(
        &'a self,
        packet: Packet,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.socket.send_to(packet.as_ref(), self.relay).await?;
            let count = count_sent();
            log_datagram("out", self.relay, packet.as_ref(), count);
            Ok(())
        })
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.socket.local_addr().map(Some)
    }
}

impl DatagramRecv for DirectRecv {
    fn recv<'a>(
        &'a mut self,
        pool: &'a mut PacketBufPool,
    ) -> Pin<Box<dyn Future<Output = io::Result<(Packet, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move {
            let mut packet = pool.get();
            let (length, source) = {
                let buffer: &mut [u8] = packet.buf_mut();
                self.socket.recv_from(buffer).await?
            };
            packet.truncate(length);
            let count = count_recv();
            log_datagram("in", source, packet.as_ref(), count);
            Ok((packet, source))
        })
    }
}
