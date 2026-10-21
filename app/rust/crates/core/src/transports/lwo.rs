//! LWO (Lightweight WireGuard Obfuscation), versions 1 and 2.
//!
//! A relay that advertises `features.lwo` speaks this on its own WireGuard address: the
//! WireGuard header is XORed with a key derived from the two public keys, so a DPI box
//! cannot recognise the packet type, and the datagrams stay plain UDP — no bridge, no
//! TCP, no extra hop. v2 additionally pads handshakes with random bytes, mixes the
//! datagram length into the obfuscation, and expects the WireGuard timers from
//! [`timer_params`].
//!
//! Ported from Mullvad's `tunnel-obfuscation/src/lwo/{mod,v2}.rs`, and from the
//! `gotatun_transport/lwo.rs` wrapper the official client uses. The framing has to match
//! the relay byte for byte: one wrong marker bit reads as a plain WireGuard packet with
//! a garbage type, and the handshake simply never completes.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use gotatun::noise::TimerParams;
use gotatun::packet::{Packet, PacketBufPool};
use rand::{Rng, RngCore};
use serde::Deserialize;
use tokio::net::UdpSocket;
use x25519_dalek::{PublicKey, StaticSecret};

use super::{
    count_recv, count_sent, log_datagram, packet_kind, DatagramRecv, DatagramSend, RecvPipe,
    SendPipe, Transport,
};

// WireGuard message types, from the first byte of a plaintext packet.
const HANDSHAKE_INITIATION: u8 = 1;
const HANDSHAKE_RESPONSE: u8 = 2;
const COOKIE_REPLY: u8 = 3;
const DATA: u8 = 4;

const HANDSHAKE_INITIATION_SIZE: usize = 148;
const HANDSHAKE_RESPONSE_SIZE: usize = 92;
const COOKIE_REPLY_SIZE: usize = 64;
/// Data header (type, reserved, receiver index, counter) plus the 16-byte AEAD tag.
const DATA_OVERHEAD_SIZE: usize = 32;

/// Bit set in byte 1 that marks a v1 packet as obfuscated.
const OBFUSCATION_BIT: u8 = 0b1000_0000;

/// v2 marker in byte 1: bit 7 clear, bit 6 set.
const MARKER_MASK: u8 = 0b1100_0000;
const MARKER: u8 = 0b0100_0000;

/// v2 obfuscates only the first 16 bytes of a data packet: the header. The payload and the
/// tag above it are left alone, and the tag is what authenticates the packet anyway.
const DATA_PROTECTED_SIZE: usize = 16;

/// Maximum random padding v2 appends to a handshake.
const MAX_PADDING: usize = 256;

/// The result of [`deobfuscate_v2`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// The packet does not claim LWO v2; forward it as plain WireGuard.
    Plain,
    /// A valid LWO v2 packet, deobfuscated in place. A handshake is padded, so the packet
    /// must be truncated to `trim_to` before WireGuard sees it.
    Lwo { trim_to: Option<usize> },
    /// The packet claims LWO v2 but does not validate. Drop it.
    Invalid,
}

/// Settings the extension passes as JSON: `{"version":1}` or `{"version":2}`.
#[derive(Deserialize)]
struct Settings {
    version: u8,
}

/// Per-direction obfuscation keys. The relay uses the client's public key for the traffic
/// it sends and its own public key for the traffic it receives, which is the mirror of
/// these, so only public keys ever leave the device.
#[derive(Debug, Clone, Copy)]
enum Keys {
    /// v1: a packet from the relay is XORed with the client's public key, a packet to the
    /// relay with the relay's.
    V1 { rx_key: [u8; 32], tx_key: [u8; 32] },
    /// v2: both directions use the relay's public key, and the length is mixed in too.
    V2 { key: [u8; 32] },
}

/// A relay told to speak LWO, at the relay's own WireGuard address.
pub struct Lwo {
    socket: Arc<UdpSocket>,
    relay: SocketAddr,
    keys: Keys,
    version: u8,
    timer_params: Option<TimerParams>,
}

impl Lwo {
    /// `peer_key` is the relay's WireGuard public key. v1 derives the client public key
    /// from the stored device key ([`crate::load_key`]); v2 needs only the server key.
    pub fn new(
        socket: UdpSocket,
        relay: SocketAddr,
        peer_key: Option<[u8; 32]>,
        settings: &str,
    ) -> Result<Self, String> {
        let settings: Settings =
            serde_json::from_str(settings).map_err(|error| format!("lwo settings: {error}"))?;
        let server_key =
            peer_key.ok_or_else(|| "lwo: the relay's public key is required".to_string())?;
        let keys = match settings.version {
            1 => Keys::V1 {
                rx_key: client_public_key()?,
                tx_key: server_key,
            },
            2 => Keys::V2 { key: server_key },
            other => return Err(format!("lwo: unsupported version {other}")),
        };
        Ok(Self {
            socket: Arc::new(socket),
            relay,
            keys,
            version: settings.version,
            timer_params: (settings.version == 2).then(timer_params),
        })
    }
}

/// The device's public key, derived from the private key the engine will use.
///
/// The private key never leaves the process; the relay only needs the public half as the
/// v1 receive key.
fn client_public_key() -> Result<[u8; 32], String> {
    let secret = crate::load_key().ok_or("lwo: no device key; sign in again")?;
    Ok(PublicKey::from(&StaticSecret::from(secret)).to_bytes())
}

/// WireGuard timers Mullvad's LWO v2 relays expect, from `lwo::v2::timers` upstream.
///
/// The shortened deadlines are part of v2: a handshake retransmit after five seconds and
/// a passive keepalive after ten are within what the relay's obfuscation is tuned for.
/// gotatun exposes the override as `Peer::dangerously_with_timer_params`, and the engine
/// applies it to the peer because a transport cannot reach the peer itself.
fn timer_params() -> TimerParams {
    TimerParams {
        keepalive_timeout: Duration::from_secs(8)..=Duration::from_secs(12),
        new_handshake_timeout: Duration::from_secs(13)..=Duration::from_secs(17),
        rekey_timeout: Duration::from_millis(4750)..=Duration::from_millis(5250),
        rekey_after_time: Duration::from_secs(100)..=Duration::from_secs(120),
    }
}

impl Transport for Lwo {
    fn bind<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<(SendPipe, RecvPipe)>> + Send + 'a>> {
        Box::pin(async move {
            crate::log_line(&format!(
                "lwo v{} to {}, {} B MTU overhead",
                self.version,
                self.relay,
                self.mtu_overhead()
            ));
            let send: SendPipe = Box::new(LwoSend {
                socket: Arc::clone(&self.socket),
                relay: self.relay,
                keys: self.keys,
            });
            let recv: RecvPipe = Box::new(LwoRecv {
                socket: Arc::clone(&self.socket),
                relay: self.relay,
                keys: self.keys,
            });
            Ok((send, recv))
        })
    }

    fn mtu_overhead(&self) -> u16 {
        // Upstream reports zero for both versions, and it is true for the datagrams that
        // carry payload: v1 rewrites the header, v2 rewrites it and pads handshakes only.
        // The largest padded handshake is 148 + 256 bytes, well under the tunnel MTU.
        0
    }

    fn name(&self) -> &'static str {
        "lwo"
    }

    fn timer_params(&self) -> Option<TimerParams> {
        self.timer_params.clone()
    }
}

#[derive(Clone)]
struct LwoSend {
    socket: Arc<UdpSocket>,
    relay: SocketAddr,
    keys: Keys,
}

impl DatagramSend for LwoSend {
    fn send<'a>(
        &'a self,
        mut packet: Packet,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            // The first byte stops being the WireGuard type once it is obfuscated, so keep
            // what the diagnostic line needs before touching the packet.
            let length = packet.len();
            let first = packet.as_ref().first().copied().unwrap_or(0);
            match &self.keys {
                Keys::V1 { tx_key, .. } => {
                    let mut reserved = [0u8; 1];
                    rand::thread_rng().fill_bytes(&mut reserved);
                    obfuscate_v1(&mut packet, tx_key, reserved[0]);
                }
                Keys::V2 { key } => {
                    pad_handshake(&mut packet, &mut rand::thread_rng());
                    obfuscate_v2(&mut packet, key);
                }
            }
            self.socket.send_to(packet.as_ref(), self.relay).await?;
            let count = count_sent();
            log_obfuscated("out", self.relay, length, first, count);
            Ok(())
        })
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.socket.local_addr().map(Some)
    }
}

struct LwoRecv {
    socket: Arc<UdpSocket>,
    relay: SocketAddr,
    keys: Keys,
}

impl DatagramRecv for LwoRecv {
    fn recv<'a>(
        &'a mut self,
        pool: &'a mut PacketBufPool,
    ) -> Pin<Box<dyn Future<Output = io::Result<(Packet, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move {
            let mut dropped: u64 = 0;
            loop {
                let mut packet = pool.get();
                let (length, source) = {
                    let buffer: &mut [u8] = packet.buf_mut();
                    self.socket.recv_from(buffer).await?
                };
                // Upstream's LWO transport ignores anything that is not from the relay it
                // dialled; the obfuscation is keyed to that relay, so a stray packet is
                // never useful.
                if source != self.relay {
                    continue;
                }
                packet.truncate(length);
                let accepted = match &self.keys {
                    Keys::V1 { rx_key, .. } => {
                        deobfuscate_v1(&mut packet, rx_key);
                        true
                    }
                    Keys::V2 { key } => match deobfuscate_v2(&mut packet, key) {
                        Verdict::Plain => true,
                        Verdict::Lwo { trim_to } => {
                            if let Some(trim_to) = trim_to {
                                packet.truncate(trim_to);
                            }
                            true
                        }
                        Verdict::Invalid => false,
                    },
                };
                if !accepted {
                    // Rare enough to be worth a line, and a repeated line says the relay
                    // and this build disagree about the framing.
                    dropped += 1;
                    if dropped == 1 || dropped % 64 == 0 {
                        crate::log_line(&format!(
                            "lwo: dropped {dropped} invalid datagram(s) from {source}"
                        ));
                    }
                    continue;
                }
                let count = count_recv();
                log_datagram("in", source, packet.as_ref(), count);
                return Ok((packet, source));
            }
        })
    }
}

/// A datagram whose first byte is ciphertext cannot be labelled by `log_datagram`, so this
/// repeats its shape with the message type the sender knew.
fn log_obfuscated(direction: &str, peer: SocketAddr, length: usize, first: u8, count: u64) {
    if count > 8 && count % 64 != 0 {
        return;
    }
    crate::log_line(&format!(
        "udp {direction} {peer} {length} B {} (#{count})",
        packet_kind(first)
    ));
}

/// The part of a packet v1 XORs: the whole WireGuard header for its type.
fn header_mut(packet: &mut [u8], key_byte: u8) -> Option<&mut [u8]> {
    let header_type = *packet.first()?;
    match header_type ^ key_byte {
        HANDSHAKE_INITIATION => packet.get_mut(..HANDSHAKE_INITIATION_SIZE),
        HANDSHAKE_RESPONSE => packet.get_mut(..HANDSHAKE_RESPONSE_SIZE),
        COOKIE_REPLY => packet.get_mut(..COOKIE_REPLY_SIZE),
        DATA => packet.get_mut(..DATA_OVERHEAD_SIZE),
        _ => None,
    }
}

fn xor_bytes(data: &mut [u8], key: &[u8; 32]) {
    for (index, byte) in data.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

/// v1: XOR the header with the key and hide the reserved byte behind a random value with
/// its MSB set. `reserved` is that random byte; the caller supplies it so the framing can
/// be tested without an RNG.
fn obfuscate_v1(packet: &mut [u8], key: &[u8; 32], reserved: u8) {
    let Some(header) = header_mut(packet, 0) else {
        return;
    };
    xor_bytes(header, key);
    header[1] = reserved | OBFUSCATION_BIT;
}

/// v1: recover the header. The sender's first byte was XORed with `key[0]`, which is what
/// tells [`header_mut`] which type this was.
fn deobfuscate_v1(packet: &mut [u8], key: &[u8; 32]) {
    let Some(header) = header_mut(packet, key[0]) else {
        return;
    };
    #[cfg(debug_assertions)]
    if header[1] & OBFUSCATION_BIT == 0 {
        crate::log_line("lwo: received a v1 packet without the obfuscation bit");
        return;
    }
    xor_bytes(header, key);
    header[1] = 0;
}

/// Whether an outgoing packet is padded: only handshakes are, so the packet length does
/// not leak the session state of data traffic.
fn takes_padding(packet: &[u8]) -> bool {
    matches!(
        packet.first(),
        Some(&HANDSHAKE_INITIATION) | Some(&HANDSHAKE_RESPONSE)
    )
}

/// v2: append 1..=256 random bytes to a handshake, in place.
fn pad_handshake(packet: &mut Packet, rng: &mut impl RngCore) {
    if !takes_padding(packet.as_ref()) {
        return;
    }
    let padding = rng.gen_range(1..=MAX_PADDING);
    let buffer = packet.buf_mut();
    let start = buffer.len();
    buffer.resize(start + padding, 0);
    rng.fill_bytes(&mut buffer[start..]);
}

/// v2: XOR the protected area with `key[index] + length + index`, then write the marker
/// bytes. Padding must already have been appended: the length is part of the key stream.
fn obfuscate_v2(packet: &mut [u8], key: &[u8; 32]) {
    let Some(&message_type) = packet.first() else {
        return;
    };
    let len_mix = packet.len() as u8;
    match message_type {
        DATA => {
            if packet.len() < DATA_PROTECTED_SIZE {
                return;
            }
            xor_protected_area(&mut packet[..DATA_PROTECTED_SIZE], key, len_mix);
        }
        HANDSHAKE_INITIATION => {
            if packet.len() < HANDSHAKE_INITIATION_SIZE {
                return;
            }
            xor_protected_area(&mut packet[..HANDSHAKE_INITIATION_SIZE], key, len_mix);
        }
        HANDSHAKE_RESPONSE => {
            if packet.len() < HANDSHAKE_RESPONSE_SIZE {
                return;
            }
            xor_protected_area(&mut packet[..HANDSHAKE_RESPONSE_SIZE], key, len_mix);
        }
        // Cookie replies must stay plain, and an unknown type is not ours to rewrite.
        _ => return,
    }
    packet[1] = marker_byte(key, len_mix);
}

/// v2: validate the marker, recover the WireGuard type, and undo the protected area.
fn deobfuscate_v2(packet: &mut [u8], key: &[u8; 32]) -> Verdict {
    // Byte 1 is outside the area a data packet can be shorter than, so a short packet can
    // still claim LWO. The shortest valid one is a 32-byte data packet.
    if packet.len() < DATA_OVERHEAD_SIZE {
        return match packet.get(1) {
            Some(&reserved) if claims_lwo(reserved) => Verdict::Invalid,
            _ => Verdict::Plain,
        };
    }
    if !claims_lwo(packet[1]) {
        return Verdict::Plain;
    }

    let len_mix = packet.len() as u8;
    let valid = packet[1] == marker_byte(key, len_mix)
        && packet[2] == obfuscation_byte(key, len_mix, 2)
        && packet[3] == obfuscation_byte(key, len_mix, 3);
    if !valid {
        return Verdict::Invalid;
    }

    let message_type = packet[0] ^ key[0].wrapping_add(len_mix);
    let trim_to = match message_type {
        DATA => {
            if packet.len() < DATA_OVERHEAD_SIZE {
                return Verdict::Invalid;
            }
            xor_protected_area(&mut packet[..DATA_PROTECTED_SIZE], key, len_mix);
            None
        }
        HANDSHAKE_INITIATION => {
            let valid_len = (HANDSHAKE_INITIATION_SIZE..=HANDSHAKE_INITIATION_SIZE + MAX_PADDING)
                .contains(&packet.len());
            if !valid_len {
                return Verdict::Invalid;
            }
            xor_protected_area(&mut packet[..HANDSHAKE_INITIATION_SIZE], key, len_mix);
            Some(HANDSHAKE_INITIATION_SIZE)
        }
        HANDSHAKE_RESPONSE => {
            let valid_len = (HANDSHAKE_RESPONSE_SIZE..=HANDSHAKE_RESPONSE_SIZE + MAX_PADDING)
                .contains(&packet.len());
            if !valid_len {
                return Verdict::Invalid;
            }
            xor_protected_area(&mut packet[..HANDSHAKE_RESPONSE_SIZE], key, len_mix);
            Some(HANDSHAKE_RESPONSE_SIZE)
        }
        // A cookie reply is never obfuscated, so a packet that recovers as one is a forgery
        // or a framing error.
        COOKIE_REPLY => return Verdict::Invalid,
        _ => return Verdict::Invalid,
    };
    packet[1] = 0;
    Verdict::Lwo { trim_to }
}

fn claims_lwo(reserved: u8) -> bool {
    reserved & MARKER_MASK == MARKER
}

/// v2 marker: the low bits of the first key byte mixed with the length, plus the marker.
fn marker_byte(key: &[u8; 32], len_mix: u8) -> u8 {
    (key[0].wrapping_add(len_mix) & !MARKER_MASK) | MARKER
}

fn xor_protected_area(protected_area: &mut [u8], key: &[u8; 32], len_mix: u8) {
    for (index, byte) in protected_area.iter_mut().enumerate() {
        *byte ^= obfuscation_byte(key, len_mix, index);
    }
}

/// The value XORed into byte `index` of the protected area. The length is in here so the
/// same plaintext at two padded lengths does not produce the same bytes.
fn obfuscation_byte(key: &[u8; 32], len_mix: u8, index: usize) -> u8 {
    key[index % 32]
        .wrapping_add(len_mix)
        .wrapping_add(index as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    const KEY: [u8; 32] = [0xef; 32];

    /// Deterministic stand-in for the OS RNG in tests.
    struct FixedRng(u8);

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            u32::from(self.0)
        }

        fn next_u64(&mut self) -> u64 {
            u64::from(self.0)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(self.0);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn packet_of(length: usize, message_type: u8) -> Vec<u8> {
        let mut packet: Vec<u8> = (0..length)
            .map(|index| (index as u8).wrapping_mul(37))
            .collect();
        packet[0] = message_type;
        packet[1..4].fill(0);
        packet
    }

    fn packet(bytes: &[u8]) -> Packet {
        Packet::from_bytes(BytesMut::from(bytes))
    }

    #[test]
    fn v1_roundtrip_data() {
        let original = packet_of(DATA_OVERHEAD_SIZE + 100, DATA);
        let mut packet = original.clone();

        obfuscate_v1(&mut packet, &KEY, 0x5a);
        assert_eq!(packet[1], 0x5a | OBFUSCATION_BIT);
        assert_ne!(packet[..DATA_OVERHEAD_SIZE], original[..DATA_OVERHEAD_SIZE]);
        assert_eq!(
            packet[DATA_OVERHEAD_SIZE..],
            original[DATA_OVERHEAD_SIZE..],
            "payload should be unchanged"
        );

        deobfuscate_v1(&mut packet, &KEY);
        assert_eq!(packet, original);
    }

    #[test]
    fn v1_roundtrip_handshake() {
        let original = packet_of(HANDSHAKE_INITIATION_SIZE, HANDSHAKE_INITIATION);
        let mut packet = original.clone();
        obfuscate_v1(&mut packet, &KEY, 0x01);
        deobfuscate_v1(&mut packet, &KEY);
        assert_eq!(packet, original);

        let original = packet_of(HANDSHAKE_RESPONSE_SIZE, HANDSHAKE_RESPONSE);
        let mut packet = original.clone();
        obfuscate_v1(&mut packet, &KEY, 0x7f);
        deobfuscate_v1(&mut packet, &KEY);
        assert_eq!(packet, original);
    }

    #[test]
    fn v1_short_packet_is_left_alone() {
        let mut packet = packet_of(10, DATA);
        let original = packet.clone();
        obfuscate_v1(&mut packet, &KEY, 0x11);
        assert_eq!(
            packet, original,
            "a packet shorter than its header is not ours"
        );
    }

    #[test]
    fn v2_data_roundtrip() {
        let original = packet_of(DATA_OVERHEAD_SIZE + 100, DATA);
        let mut packet = original.clone();

        obfuscate_v2(&mut packet, &KEY);
        assert_eq!(packet[1], marker_byte(&KEY, packet.len() as u8));
        assert_eq!(
            packet[DATA_PROTECTED_SIZE..],
            original[DATA_PROTECTED_SIZE..],
            "only the header is protected"
        );

        assert_eq!(
            deobfuscate_v2(&mut packet, &KEY),
            Verdict::Lwo { trim_to: None }
        );
        assert_eq!(packet, original);
    }

    #[test]
    fn v2_padded_handshake_roundtrip() {
        for padding in [1usize, 37, MAX_PADDING] {
            let original = packet_of(HANDSHAKE_INITIATION_SIZE + padding, HANDSHAKE_INITIATION);
            let mut packet = original.clone();
            obfuscate_v2(&mut packet, &KEY);

            assert_eq!(
                deobfuscate_v2(&mut packet, &KEY),
                Verdict::Lwo {
                    trim_to: Some(HANDSHAKE_INITIATION_SIZE)
                }
            );
            assert_eq!(
                packet[..HANDSHAKE_INITIATION_SIZE],
                original[..HANDSHAKE_INITIATION_SIZE]
            );
        }

        let original = packet_of(HANDSHAKE_RESPONSE_SIZE + 5, HANDSHAKE_RESPONSE);
        let mut packet = original.clone();
        obfuscate_v2(&mut packet, &KEY);
        assert_eq!(
            deobfuscate_v2(&mut packet, &KEY),
            Verdict::Lwo {
                trim_to: Some(HANDSHAKE_RESPONSE_SIZE)
            }
        );
        assert_eq!(
            packet[..HANDSHAKE_RESPONSE_SIZE],
            original[..HANDSHAKE_RESPONSE_SIZE]
        );
    }

    #[test]
    fn v2_only_handshakes_are_padded() {
        let mut data = packet(&packet_of(DATA_OVERHEAD_SIZE + 100, DATA));
        pad_handshake(&mut data, &mut FixedRng(0x55));
        assert_eq!(
            data.len(),
            DATA_OVERHEAD_SIZE + 100,
            "data packets are not padded"
        );

        let mut init = packet(&packet_of(HANDSHAKE_INITIATION_SIZE, HANDSHAKE_INITIATION));
        pad_handshake(&mut init, &mut FixedRng(0x55));
        assert!(
            (HANDSHAKE_INITIATION_SIZE + 1..=HANDSHAKE_INITIATION_SIZE + MAX_PADDING)
                .contains(&init.len())
        );
        assert_eq!(
            init.as_ref()[HANDSHAKE_INITIATION_SIZE..],
            vec![0x55; init.len() - HANDSHAKE_INITIATION_SIZE],
            "padding is random bytes"
        );
    }

    #[test]
    fn v2_cookie_reply_and_plain_traffic_pass_through() {
        let cookie = packet_of(COOKIE_REPLY_SIZE, COOKIE_REPLY);
        let mut obfuscated = cookie.clone();
        obfuscate_v2(&mut obfuscated, &KEY);
        assert_eq!(obfuscated, cookie, "cookie replies must not be obfuscated");
        assert_eq!(deobfuscate_v2(&mut obfuscated, &KEY), Verdict::Plain);
        assert_eq!(obfuscated, cookie);

        let plain = packet_of(DATA_OVERHEAD_SIZE + 100, DATA);
        let mut received = plain.clone();
        assert_eq!(deobfuscate_v2(&mut received, &KEY), Verdict::Plain);
        assert_eq!(received, plain);
    }

    #[test]
    fn v2_tampered_packets_are_dropped() {
        for byte in 1..4 {
            let mut packet = packet_of(DATA_OVERHEAD_SIZE + 100, DATA);
            obfuscate_v2(&mut packet, &KEY);
            packet[byte] ^= 0x01;
            // Flipping bit 6 of byte 1 can also clear the marker and make the packet
            // plain; bytes 2 and 3 must always fail validation.
            assert_ne!(
                deobfuscate_v2(&mut packet, &KEY),
                Verdict::Lwo { trim_to: None },
                "tampered byte {byte} must not validate"
            );
        }

        // A packet that validates but recovers as a cookie reply is a forgery.
        let mut forged = packet_of(COOKIE_REPLY_SIZE, COOKIE_REPLY);
        let len_mix = forged.len() as u8;
        forged[0] = COOKIE_REPLY ^ KEY[0].wrapping_add(len_mix);
        forged[1] = marker_byte(&KEY, len_mix);
        forged[2] = obfuscation_byte(&KEY, len_mix, 2);
        forged[3] = obfuscation_byte(&KEY, len_mix, 3);
        assert_eq!(deobfuscate_v2(&mut forged, &KEY), Verdict::Invalid);
    }

    #[test]
    fn v2_invalid_lengths_are_dropped() {
        // A data packet shorter than 32 bytes claiming LWO.
        let mut short = packet_of(DATA_OVERHEAD_SIZE - 1, DATA);
        short[1] = marker_byte(&KEY, short.len() as u8);
        assert_eq!(deobfuscate_v2(&mut short, &KEY), Verdict::Invalid);

        // An over-padded handshake.
        let length = HANDSHAKE_INITIATION_SIZE + MAX_PADDING + 1;
        let mut oversized = packet_of(length, HANDSHAKE_INITIATION);
        let len_mix = length as u8;
        oversized[0] = HANDSHAKE_INITIATION ^ KEY[0].wrapping_add(len_mix);
        oversized[1] = marker_byte(&KEY, len_mix);
        oversized[2] = obfuscation_byte(&KEY, len_mix, 2);
        oversized[3] = obfuscation_byte(&KEY, len_mix, 3);
        assert_eq!(deobfuscate_v2(&mut oversized, &KEY), Verdict::Invalid);
    }

    #[test]
    fn v2_length_is_mixed_into_the_obfuscation() {
        let original = packet_of(DATA_OVERHEAD_SIZE + 100, DATA);
        let mut first = original.clone();
        obfuscate_v2(&mut first, &KEY);

        let mut longer = original.clone();
        longer.push(0);
        obfuscate_v2(&mut longer, &KEY);

        assert_ne!(first[..DATA_PROTECTED_SIZE], longer[..DATA_PROTECTED_SIZE]);

        // The same packet at the wrong length no longer validates.
        let mut truncated = first.clone();
        truncated.pop();
        assert_ne!(
            deobfuscate_v2(&mut truncated, &KEY),
            Verdict::Lwo { trim_to: None }
        );
    }

    #[test]
    fn v2_send_pipeline_pads_then_obfuscates() {
        let original = packet_of(HANDSHAKE_INITIATION_SIZE, HANDSHAKE_INITIATION);
        let mut packet = packet(&original);
        pad_handshake(&mut packet, &mut FixedRng(0x33));
        let padded_len = packet.len();
        assert!(padded_len > HANDSHAKE_INITIATION_SIZE);
        obfuscate_v2(&mut packet, &KEY);
        assert_eq!(packet[1], marker_byte(&KEY, padded_len as u8));
        assert_eq!(
            deobfuscate_v2(&mut packet, &KEY),
            Verdict::Lwo {
                trim_to: Some(HANDSHAKE_INITIATION_SIZE)
            }
        );
        // The deobfuscated prefix is the original handshake; the padding above it is left
        // for the transport to trim, exactly like the receive path does.
        assert_eq!(&packet.as_ref()[..HANDSHAKE_INITIATION_SIZE], &original[..]);
    }

    /// Known-answer vectors produced by an independent Python transcription of
    /// `lwo/mod.rs` and `lwo/v2.rs`. They pin the exact bytes the relay expects, which a
    /// round-trip test cannot: an encoder and decoder with the same bug agree with each
    /// other.
    #[test]
    fn known_answers_match_upstream_framing() {
        // v1 data: header XORed with the key, byte 1 replaced by the random byte + MSB.
        let original = packet_of(DATA_OVERHEAD_SIZE + 100, DATA);
        let mut v1 = original.clone();
        obfuscate_v1(&mut v1, &KEY, 0x5a);
        assert_eq!(
            &v1[..DATA_OVERHEAD_SIZE],
            &[
                0xeb, 0xda, 0xef, 0xef, 0x7b, 0x56, 0x31, 0xec, 0xc7, 0xa2, 0x9d, 0x78, 0x53, 0x0e,
                0xe9, 0xc4, 0xbf, 0x9a, 0x75, 0x50, 0x0b, 0xe6, 0xc1, 0xbc, 0x97, 0x72, 0x2d, 0x08,
                0xe3, 0xde, 0xb9, 0x94,
            ],
            "v1 data header"
        );

        // v2 data: 16 protected bytes and the marker in byte 1.
        let mut v2 = original.clone();
        obfuscate_v2(&mut v2, &KEY);
        assert_eq!(
            &v2[..16],
            &[
                0x77, 0x73, 0x75, 0x76, 0xe3, 0xc1, 0xa7, 0x79, 0x53, 0x31, 0x0f, 0xe9, 0xc3, 0x61,
                0x87, 0xa9,
            ],
            "v2 data header"
        );

        // v2 padded handshake initiation: the whole protected area and the marker.
        let mut init = packet_of(HANDSHAKE_INITIATION_SIZE + 37, HANDSHAKE_INITIATION);
        obfuscate_v2(&mut init, &KEY);
        assert_eq!(
            &init[..148],
            &[
                0xa9, 0x68, 0xaa, 0xab, 0x38, 0x14, 0x70, 0xac, 0x98, 0xfc, 0xc0, 0x24, 0x08, 0x54,
                0xb0, 0x9c, 0xe8, 0xcc, 0x20, 0x04, 0x58, 0xb4, 0x90, 0xec, 0xb8, 0x5c, 0x00, 0x24,
                0xc8, 0xf4, 0x90, 0xbc, 0x68, 0x0c, 0x20, 0xc4, 0xf8, 0x94, 0xb0, 0x6c, 0x18, 0x3c,
                0xc0, 0xe4, 0x88, 0x54, 0x70, 0x1c, 0x28, 0xcc, 0xe0, 0x84, 0x58, 0x74, 0x10, 0x2c,
                0xf8, 0xdc, 0x80, 0x64, 0x48, 0x34, 0x10, 0xfc, 0xa8, 0x8c, 0x60, 0x44, 0x38, 0x14,
                0xf0, 0xac, 0x98, 0x7c, 0x40, 0x24, 0x08, 0xd4, 0xb0, 0x9c, 0x68, 0x4c, 0x20, 0x04,
                0xd8, 0xb4, 0x90, 0x6c, 0xb8, 0xdc, 0x00, 0x24, 0x48, 0x74, 0x90, 0xbc, 0xe8, 0x0c,
                0x20, 0x44, 0x78, 0x94, 0xb0, 0xec, 0x18, 0x3c, 0x40, 0x64, 0x88, 0xd4, 0xf0, 0x1c,
                0x28, 0x4c, 0x60, 0x84, 0xd8, 0xf4, 0x10, 0x2c, 0x78, 0x5c, 0x80, 0xe4, 0xc8, 0x34,
                0x10, 0x7c, 0xa8, 0x8c, 0xe0, 0xc4, 0x38, 0x14, 0x70, 0xac, 0x98, 0xfc, 0xc0, 0x24,
                0x08, 0x54, 0xb0, 0x9c, 0xe8, 0xcc, 0x20, 0x04,
            ],
            "v2 padded handshake initiation"
        );
        assert_eq!(
            init[1],
            marker_byte(&KEY, (HANDSHAKE_INITIATION_SIZE + 37) as u8)
        );
    }

    #[tokio::test]
    async fn settings_select_the_version_and_v2_timers() {
        let relay: SocketAddr = "127.0.0.1:51820".parse().expect("relay address");
        let bind = || async { UdpSocket::bind("127.0.0.1:0").await.expect("bind") };

        let v2 = Lwo::new(bind().await, relay, Some([7u8; 32]), r#"{"version":2}"#)
            .expect("v2 settings");
        assert!(v2.timer_params().is_some(), "v2 needs the upstream timers");
        assert_eq!(v2.name(), "lwo");

        // The factory arm is what the extension reaches; it must accept the LWO name and
        // carry the timer override out to the engine.
        // The factory takes the standard-library socket the extension opened; it converts
        // it inside the runtime.
        let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        std_socket.set_nonblocking(true).expect("nonblocking");
        let factory = super::super::TransportFactory::new(
            crate::transports::RelaySocket::Udp(std_socket),
            relay,
            None,
            "lwo",
            r#"{"version":2}"#,
            Some([7u8; 32]),
        )
        .expect("factory arm");
        assert!(factory.timer_params().is_some());

        // v1 derives its receive key from the registered device key, which this test
        // process does not have.
        assert!(Lwo::new(bind().await, relay, Some([7u8; 32]), r#"{"version":1}"#).is_err());
        // A relay key and a known version are both mandatory.
        assert!(Lwo::new(bind().await, relay, None, r#"{"version":2}"#).is_err());
        assert!(Lwo::new(bind().await, relay, Some([7u8; 32]), r#"{"version":3}"#).is_err());
        assert!(Lwo::new(bind().await, relay, Some([7u8; 32]), "").is_err());
    }
}
