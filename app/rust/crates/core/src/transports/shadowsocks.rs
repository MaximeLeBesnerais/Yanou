//! Mullvad's Shadowsocks transport.
//!
//! On a filtered network the relay IPs are unreachable — the handshake initiation leaves
//! the device and nothing comes back, on every port. Mullvad's own answer, and the reason
//! the bridge relay list exists, is to reach a bridge instead and let it forward the
//! WireGuard datagrams. That is what `shadowsocks` here does: AEAD-encrypted UDP packets
//! to the bridge, each carrying the WireGuard endpoint as its destination address.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use gotatun::packet::{Packet, PacketBufPool};
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::udprelay::proxy_socket::{ProxySocket, UdpSocketType};
use shadowsocks::relay::Address;
use tokio::net::UdpSocket;

use super::{
    count_recv, count_sent, log_datagram, DatagramRecv, DatagramSend, RecvPipe, SendPipe,
    Transport,
};

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

/// A bridge relay, speaking Shadowsocks to `bridge` and forwarding to `relay`.
pub struct Shadowsocks {
    proxy: Arc<Proxy>,
    bridge: SocketAddr,
    relay: SocketAddr,
}

impl Shadowsocks {
    pub fn new(socket: UdpSocket, relay: SocketAddr, bridge: SocketAddr) -> Result<Self, String> {
        let context = Context::new_shared(ServerType::Local);
        let config = ServerConfig::new(bridge, BRIDGE_PASSWORD, BRIDGE_CIPHER)
            .map_err(|error| format!("bridge config: {error}"))?;
        let proxy = ProxySocket::from_socket(
            UdpSocketType::Client,
            context,
            &config,
            shadowsocks::net::UdpSocket::from(socket),
        );
        Ok(Self {
            proxy: Arc::new(proxy),
            bridge,
            relay,
        })
    }
}

impl Transport for Shadowsocks {
    fn bind<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<(SendPipe, RecvPipe)>> + Send + 'a>> {
        Box::pin(async move {
            let send: SendPipe = Box::new(ShadowsocksSend {
                proxy: Arc::clone(&self.proxy),
                bridge: self.bridge,
                relay: self.relay,
            });
            let recv: RecvPipe = Box::new(ShadowsocksRecv {
                proxy: Arc::clone(&self.proxy),
                relay: self.relay,
                // `ProxySocket::recv_from` decrypts in place, so it needs a full-size buffer.
                buffer: vec![0u8; 65_536],
            });
            Ok((send, recv))
        })
    }

    fn mtu_overhead(&self) -> u16 {
        // [salt][address][payload][tag], per https://shadowsocks.org/doc/aead.html.
        let overhead = BRIDGE_CIPHER.salt_len()
            + Address::SocketAddress(shadowsocks_inner()).serialized_len()
            + BRIDGE_CIPHER.tag_len();
        u16::try_from(overhead).unwrap_or(u16::MAX)
    }

    fn name(&self) -> &'static str {
        "shadowsocks"
    }
}

#[derive(Clone)]
struct ShadowsocksSend {
    proxy: Arc<Proxy>,
    bridge: SocketAddr,
    relay: SocketAddr,
}

struct ShadowsocksRecv {
    proxy: Arc<Proxy>,
    relay: SocketAddr,
    buffer: Vec<u8>,
}

impl DatagramSend for ShadowsocksSend {
    fn send<'a>(
        &'a self,
        packet: Packet,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.proxy
                .send_to(
                    self.bridge,
                    &Address::SocketAddress(shadowsocks_inner()),
                    packet.as_ref(),
                )
                .await
                .map_err(io::Error::other)?;
            let count = count_sent();
            log_datagram("out", self.relay, packet.as_ref(), count);
            Ok(())
        })
    }
}

impl DatagramRecv for ShadowsocksRecv {
    fn recv<'a>(
        &'a mut self,
        _pool: &'a mut PacketBufPool,
    ) -> Pin<Box<dyn Future<Output = io::Result<(Packet, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move {
            let (length, _from, _destination, _control) = self
                .proxy
                .recv_from(&mut self.buffer)
                .await
                .map_err(io::Error::other)?;
            let packet = Packet::from_bytes(bytes::BytesMut::from(&self.buffer[..length]));
            let count = count_recv();
            log_datagram("in", self.relay, packet.as_ref(), count);
            Ok((packet, self.relay))
        })
    }
}
