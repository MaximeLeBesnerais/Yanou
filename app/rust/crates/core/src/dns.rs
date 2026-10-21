//! In-tunnel DNS redirect.
//!
//! The platform resolver does not use `VpnConfig.dnsAddresses` on this build: the VPN takes
//! the routes but not the default-network role, so `connection.getAddressesByName` keeps
//! asking the Wi-Fi resolvers and content blocking never sees the query. This layer sits
//! between the tun device and gotatun and removes that dependency from the data path:
//!
//! - app → tunnel ([`IpRecv`]): a plaintext IPv4 UDP datagram whose destination port is 53
//!   is rewritten to the tunnel resolver, remembering the address the app dialled under the
//!   packet's source port;
//! - tunnel → app ([`IpSend`]): a reply from the resolver on port 53 is rewritten back to
//!   that remembered address.
//!
//! IPv4 makes the checksum work cheap: the UDP checksum is set to zero, which means "no
//! checksum" in IPv4, and only the IPv4 header checksum has to be recomputed. IPv6 is not
//! touched because a zero UDP checksum is illegal there (and recomputing it would need the
//! pseudo-header, which is not worth a second path until something asks for it).

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};

/// Every plaintext DNS query, whichever address the application dialled.
const DNS_PORT: u16 = 53;
/// How long a query's source port is remembered for the reply.
///
/// Long enough for a retry over the same socket (the stub resolver retries within a couple
/// of seconds), short enough that a late reply cannot be matched to an unrelated query that
/// happens to reuse the port.
const MAPPING_TTL: Duration = Duration::from_secs(5);
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
/// `IpNextProtocol::Udp`; kept as a number so this module does not depend on the enum's
/// representation beyond the wire format.
const IPPROTO_UDP: u8 = 17;
/// Offset of the IPv4 header checksum field.
const IPV4_CHECKSUM_OFFSET: usize = 10;

/// The two directions the layer sees.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// Read from the tun: sent by an application towards the tunnel.
    Outbound,
    /// Written to the tun: a reply coming back through the tunnel.
    Inbound,
}

/// Wraps a tun device and rewrites plaintext IPv4 DNS in both directions.
///
/// `resolver` is `None` when the extension did not ask for the redirect (a private custom
/// resolver, or an IPv6 one), in which case the layer is a pass-through. Cloning shares the
/// mapping, which is what makes the two halves the engine builds see the same source ports.
#[derive(Clone)]
pub(crate) struct DnsRedirect<T> {
    inner: T,
    state: Option<Arc<Mutex<DnsState>>>,
}

impl<T> DnsRedirect<T> {
    pub(crate) fn new(inner: T, resolver: Option<Ipv4Addr>) -> Self {
        Self {
            inner,
            state: resolver.map(|resolver| Arc::new(Mutex::new(DnsState::new(resolver)))),
        }
    }
}

impl<T: IpSend> IpSend for DnsRedirect<T> {
    fn send(&mut self, packet: Packet<Ip>) -> impl Future<Output = io::Result<()>> + Send {
        let packet = rewrite_packet(
            packet,
            Direction::Inbound,
            self.state.as_ref(),
            Instant::now(),
        );
        async move {
            match packet {
                Some(packet) => self.inner.send(packet).await,
                // Rewriting only ever fails for a packet that is not a valid IP packet in
                // the first place; dropping it is the same thing the engine would do.
                None => Ok(()),
            }
        }
    }
}

impl<T: IpRecv> IpRecv for DnsRedirect<T> {
    fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> impl Future<Output = io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a>> + Send {
        let state = self.state.clone();
        let inner = &mut self.inner;
        async move {
            let packets = inner.recv(pool).await?;
            Ok(packets.filter_map(move |packet| {
                rewrite_packet(packet, Direction::Outbound, state.as_ref(), Instant::now())
            }))
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.inner.mtu()
    }
}

/// Rewrites one packet, returning `None` only when the packet could not be re-validated.
///
/// Non-DNS traffic takes the fast path: the packet is only inspected, never copied, and the
/// mapping lock is not taken.
fn rewrite_packet(
    packet: Packet<Ip>,
    direction: Direction,
    state: Option<&Arc<Mutex<DnsState>>>,
    now: Instant,
) -> Option<Packet<Ip>> {
    let Some(state) = state else {
        return Some(packet);
    };
    let mut raw = packet.into_bytes();
    let eligible = parse_udp4(raw.buf_mut()).is_some_and(|view| match direction {
        Direction::Outbound => view.destination_port == DNS_PORT,
        Direction::Inbound => view.source_port == DNS_PORT,
    });
    if eligible {
        if let Ok(mut state) = state.lock() {
            let bytes = raw.buf_mut();
            match direction {
                Direction::Outbound => rewrite_outbound(bytes, &mut state, now),
                Direction::Inbound => rewrite_inbound(bytes, &mut state, now),
            };
        }
    }
    // The packet was a valid `Ip` packet on the way in and only header fields of the same
    // size were changed, so this can only fail if gotatun itself handed us something odd.
    raw.try_into_ip().ok()
}

/// Remembered query: where it was dialled and when the mapping stops being useful.
struct Mapping {
    destination: Ipv4Addr,
    expires_at: Instant,
}

/// Source port → original DNS destination.
struct DnsState {
    resolver: Ipv4Addr,
    mappings: HashMap<u16, Mapping>,
}

impl DnsState {
    fn new(resolver: Ipv4Addr) -> Self {
        Self {
            resolver,
            mappings: HashMap::new(),
        }
    }

    /// Stores the address the application dialled under the port its query came from.
    fn remember_at(&mut self, source_port: u16, destination: Ipv4Addr, now: Instant) {
        self.mappings.retain(|_, mapping| mapping.expires_at > now);
        self.mappings.insert(
            source_port,
            Mapping {
                destination,
                expires_at: now + MAPPING_TTL,
            },
        );
    }

    /// Takes (and forgets) the original destination for a reply to `destination_port`.
    ///
    /// An expired mapping is removed and treated as absent: guessing an address would send
    /// the reply to whatever the port belonged to five seconds ago.
    fn take_at(&mut self, destination_port: u16, now: Instant) -> Option<Ipv4Addr> {
        let mapping = self.mappings.remove(&destination_port)?;
        (mapping.expires_at > now).then_some(mapping.destination)
    }
}

/// The fields of one unfragmented IPv4 UDP datagram this module needs.
#[derive(Clone, Copy)]
struct Udp4View {
    header_len: usize,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
}

/// Parses enough of an IPv4 packet to rewrite a DNS datagram, without trusting it.
///
/// Fragments are rejected: only the first fragment carries the UDP header, and rewriting
/// that one without its siblings would deliver a query the tunnel resolver cannot answer.
fn parse_udp4(bytes: &[u8]) -> Option<Udp4View> {
    if bytes.len() < IPV4_HEADER_LEN + UDP_HEADER_LEN {
        return None;
    }
    if bytes[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(bytes[0] & 0x0f) * 4;
    if header_len < IPV4_HEADER_LEN || header_len + UDP_HEADER_LEN > bytes.len() {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if total_len < header_len + UDP_HEADER_LEN || total_len > bytes.len() {
        return None;
    }
    if bytes[9] != IPPROTO_UDP {
        return None;
    }
    // 0x2000 is MF, 0x1fff is the fragment offset. DF is fine and common.
    let flags_and_offset = u16::from_be_bytes([bytes[6], bytes[7]]);
    if flags_and_offset & 0x2000 != 0 || flags_and_offset & 0x1fff != 0 {
        return None;
    }
    let udp_len = usize::from(u16::from_be_bytes([
        bytes[header_len + 4],
        bytes[header_len + 5],
    ]));
    if udp_len < UDP_HEADER_LEN || header_len + udp_len > total_len {
        return None;
    }
    Some(Udp4View {
        header_len,
        source: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
        destination: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
        source_port: u16::from_be_bytes([bytes[header_len], bytes[header_len + 1]]),
        destination_port: u16::from_be_bytes([bytes[header_len + 2], bytes[header_len + 3]]),
    })
}

/// Sends one query to the tunnel resolver and remembers where it was really going.
fn rewrite_outbound(bytes: &mut [u8], state: &mut DnsState, now: Instant) -> bool {
    let Some(view) = parse_udp4(bytes) else {
        return false;
    };
    if view.destination_port != DNS_PORT {
        return false;
    }
    bytes[16..20].copy_from_slice(&state.resolver.octets());
    refresh_ipv4_checksums(bytes, &view);
    state.remember_at(view.source_port, view.destination, now);
    true
}

/// Puts the address the application dialled back into a reply from the resolver.
fn rewrite_inbound(bytes: &mut [u8], state: &mut DnsState, now: Instant) -> bool {
    let Some(view) = parse_udp4(bytes) else {
        return false;
    };
    if view.source_port != DNS_PORT || view.source != state.resolver {
        return false;
    }
    let Some(destination) = state.take_at(view.destination_port, now) else {
        return false;
    };
    bytes[12..16].copy_from_slice(&destination.octets());
    refresh_ipv4_checksums(bytes, &view);
    true
}

/// Clears the UDP checksum and makes the IPv4 header checksum match the rewritten addresses.
fn refresh_ipv4_checksums(bytes: &mut [u8], view: &Udp4View) {
    let checksum_offset = view.header_len + 6;
    bytes[checksum_offset..checksum_offset + 2].fill(0);
    let checksum = ipv4_header_checksum(&bytes[..view.header_len]);
    bytes[IPV4_CHECKSUM_OFFSET..IPV4_CHECKSUM_OFFSET + 2].copy_from_slice(&checksum.to_be_bytes());
}

/// The Internet checksum of an IPv4 header, treating the checksum field itself as zero.
fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut offset = 0;
    while offset + 1 < header.len() {
        if offset != IPV4_CHECKSUM_OFFSET {
            sum += u32::from(u16::from_be_bytes([header[offset], header[offset + 1]]));
        }
        offset += 2;
    }
    if offset < header.len() {
        sum += u32::from(u16::from_be_bytes([header[offset], 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use std::sync::MutexGuard;

    use bytes::BytesMut;

    const RESOLVER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
    const APP: Ipv4Addr = Ipv4Addr::new(10, 64, 0, 2);
    const PUBLIC: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

    fn state() -> Arc<Mutex<DnsState>> {
        Arc::new(Mutex::new(DnsState::new(RESOLVER)))
    }

    fn mapping_count(state: &Arc<Mutex<DnsState>>) -> usize {
        state.lock().expect("dns state").mappings.len()
    }

    fn guard(state: &Arc<Mutex<DnsState>>) -> MutexGuard<'_, DnsState> {
        state.lock().expect("dns state")
    }

    fn packet_from(bytes: Vec<u8>) -> Packet<Ip> {
        Packet::<[u8]>::from_bytes(BytesMut::from(&bytes[..]))
            .try_into_ip()
            .expect("test packet is a valid IP packet")
    }

    fn plain(packet: Packet<Ip>) -> Vec<u8> {
        packet.into_bytes().as_ref().to_vec()
    }

    fn rewrite(
        bytes: Vec<u8>,
        direction: Direction,
        state: &Arc<Mutex<DnsState>>,
        now: Instant,
    ) -> Vec<u8> {
        let packet = rewrite_packet(packet_from(bytes), direction, Some(state), now)
            .expect("packet survives the rewrite");
        plain(packet)
    }

    /// A hand-built IPv4 UDP packet, with a non-zero UDP checksum that a rewrite must clear.
    fn ipv4_udp(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = UDP_HEADER_LEN + payload.len();
        let total_len = IPV4_HEADER_LEN + udp_len;
        let mut bytes = vec![0u8; total_len];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        bytes[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF, unfragmented
        bytes[8] = 64;
        bytes[9] = IPPROTO_UDP;
        bytes[12..16].copy_from_slice(&source.octets());
        bytes[16..20].copy_from_slice(&destination.octets());
        bytes[20..22].copy_from_slice(&source_port.to_be_bytes());
        bytes[22..24].copy_from_slice(&destination_port.to_be_bytes());
        bytes[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        bytes[26..28].copy_from_slice(&0xbeefu16.to_be_bytes());
        bytes[28..].copy_from_slice(payload);
        seal_ipv4_header(&mut bytes);
        bytes
    }

    /// A hand-built IPv4 TCP packet; only the header matters for "must be untouched".
    fn ipv4_tcp(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let total_len = IPV4_HEADER_LEN + 20;
        let mut bytes = vec![0u8; total_len];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        bytes[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 6;
        bytes[12..16].copy_from_slice(&source.octets());
        bytes[16..20].copy_from_slice(&destination.octets());
        bytes[20..22].copy_from_slice(&source_port.to_be_bytes());
        bytes[22..24].copy_from_slice(&destination_port.to_be_bytes());
        bytes[32] = 0x50; // TCP data offset: five 32-bit words
        seal_ipv4_header(&mut bytes);
        bytes
    }

    /// A hand-built IPv6 UDP packet with a non-zero (and deliberately unrecomputed) checksum.
    fn ipv6_udp(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = UDP_HEADER_LEN + payload.len();
        let mut bytes = vec![0u8; 40 + udp_len];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        bytes[6] = IPPROTO_UDP;
        bytes[7] = 64;
        bytes[8..24].copy_from_slice(&source.octets());
        bytes[24..40].copy_from_slice(&destination.octets());
        bytes[40..42].copy_from_slice(&source_port.to_be_bytes());
        bytes[42..44].copy_from_slice(&destination_port.to_be_bytes());
        bytes[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
        bytes[46..48].copy_from_slice(&0x1234u16.to_be_bytes());
        bytes[48..].copy_from_slice(payload);
        bytes
    }

    fn seal_ipv4_header(bytes: &mut [u8]) {
        bytes[IPV4_CHECKSUM_OFFSET..IPV4_CHECKSUM_OFFSET + 2].fill(0);
        let checksum = ipv4_header_checksum(&bytes[..IPV4_HEADER_LEN]);
        bytes[IPV4_CHECKSUM_OFFSET..IPV4_CHECKSUM_OFFSET + 2]
            .copy_from_slice(&checksum.to_be_bytes());
    }

    fn stored_ipv4_checksum(bytes: &[u8]) -> u16 {
        u16::from_be_bytes([bytes[IPV4_CHECKSUM_OFFSET], bytes[IPV4_CHECKSUM_OFFSET + 1]])
    }

    fn stored_udp_checksum(bytes: &[u8], header_len: usize) -> u16 {
        u16::from_be_bytes([bytes[header_len + 6], bytes[header_len + 7]])
    }

    /// The Internet checksum property: summing a valid IPv4 header, checksum field
    /// included, yields 0xffff. Independent of [`ipv4_header_checksum`], so a rewritten
    /// packet is not checked against the same implementation that wrote it.
    fn ipv4_header_is_valid(bytes: &[u8]) -> bool {
        let mut sum = 0u32;
        for chunk in bytes[..IPV4_HEADER_LEN].chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum >> 16) + (sum & 0xffff);
        }
        sum as u16 == 0xffff
    }

    #[test]
    fn ipv4_checksum_matches_a_known_good_header() {
        // The worked example from gotatun's packet documentation: this header's checksum
        // is 0xc5a3.
        let header = [
            0x45, 0x83, 0x00, 0x54, 0xa3, 0x13, 0x40, 0x00, 0x40, 0x01, 0xc5, 0xa3, 0x0a, 0x8c,
            0xc2, 0xdd, 0x01, 0x02, 0x03, 0x04,
        ];
        assert_eq!(ipv4_header_checksum(&header), 0xc5a3);
        assert!(ipv4_header_is_valid(&header));
    }

    #[test]
    fn ipv4_dns_query_is_redirected_to_the_tunnel_resolver() {
        let state = state();
        let now = Instant::now();
        let bytes = rewrite(
            ipv4_udp(APP, PUBLIC, 40000, DNS_PORT, b"\x12\x34"),
            Direction::Outbound,
            &state,
            now,
        );

        assert_eq!(
            &bytes[12..16],
            &APP.octets(),
            "source address must not change"
        );
        assert_eq!(
            &bytes[16..20],
            &RESOLVER.octets(),
            "destination is the resolver"
        );
        assert_eq!(u16::from_be_bytes([bytes[20], bytes[21]]), 40000);
        assert_eq!(u16::from_be_bytes([bytes[22], bytes[23]]), DNS_PORT);
        assert_eq!(stored_udp_checksum(&bytes, IPV4_HEADER_LEN), 0);
        assert_eq!(
            stored_ipv4_checksum(&bytes),
            ipv4_header_checksum(&bytes[..IPV4_HEADER_LEN])
        );
        assert!(
            ipv4_header_is_valid(&bytes),
            "IPv4 header checksum is valid"
        );

        let mappings = guard(&state);
        let mapping = mappings
            .mappings
            .get(&40000)
            .expect("source port remembered");
        assert_eq!(mapping.destination, PUBLIC);
    }

    #[test]
    fn ipv4_dns_reply_is_rewritten_back_to_the_address_the_app_dialled() {
        let state = state();
        let now = Instant::now();
        rewrite(
            ipv4_udp(APP, PUBLIC, 40000, DNS_PORT, b"query"),
            Direction::Outbound,
            &state,
            now,
        );
        let bytes = rewrite(
            ipv4_udp(RESOLVER, APP, DNS_PORT, 40000, b"answer"),
            Direction::Inbound,
            &state,
            now + Duration::from_millis(200),
        );

        assert_eq!(
            &bytes[12..16],
            &PUBLIC.octets(),
            "source is the original resolver"
        );
        assert_eq!(&bytes[16..20], &APP.octets(), "destination stays the app");
        assert_eq!(stored_udp_checksum(&bytes, IPV4_HEADER_LEN), 0);
        assert_eq!(
            stored_ipv4_checksum(&bytes),
            ipv4_header_checksum(&bytes[..IPV4_HEADER_LEN])
        );
        assert!(
            ipv4_header_is_valid(&bytes),
            "IPv4 header checksum is valid"
        );
        assert_eq!(
            mapping_count(&state),
            0,
            "the mapping is consumed by its reply"
        );
    }

    #[test]
    fn a_reply_after_the_mapping_expires_is_left_alone() {
        let state = state();
        let now = Instant::now();
        rewrite(
            ipv4_udp(APP, PUBLIC, 40000, DNS_PORT, b"query"),
            Direction::Outbound,
            &state,
            now,
        );
        let reply = ipv4_udp(RESOLVER, APP, DNS_PORT, 40000, b"late");
        let bytes = rewrite(
            reply.clone(),
            Direction::Inbound,
            &state,
            now + MAPPING_TTL + Duration::from_millis(1),
        );

        assert_eq!(bytes, reply, "an expired mapping must not be guessed");
        assert_eq!(mapping_count(&state), 0, "the expired mapping is dropped");
    }

    #[test]
    fn a_reply_from_another_server_is_left_alone() {
        let state = state();
        let now = Instant::now();
        rewrite(
            ipv4_udp(APP, PUBLIC, 40000, DNS_PORT, b"query"),
            Direction::Outbound,
            &state,
            now,
        );
        let reply = ipv4_udp(PUBLIC, APP, DNS_PORT, 40000, b"not from the resolver");
        let bytes = rewrite(reply.clone(), Direction::Inbound, &state, now);

        assert_eq!(bytes, reply);
        assert_eq!(
            mapping_count(&state),
            1,
            "the query is still waiting for its reply"
        );
    }

    #[test]
    fn non_dns_udp_is_untouched() {
        let state = state();
        let now = Instant::now();
        for port in [443, 5353, 54] {
            let original = ipv4_udp(APP, PUBLIC, 40000, port, b"data");
            for direction in [Direction::Outbound, Direction::Inbound] {
                let bytes = rewrite(original.clone(), direction, &state, now);
                assert_eq!(bytes, original, "UDP port {port} must pass through");
            }
        }
        assert_eq!(mapping_count(&state), 0);
    }

    #[test]
    fn tcp_is_untouched_even_on_port_53() {
        let state = state();
        let now = Instant::now();
        for (source, destination, source_port, destination_port) in [
            (APP, PUBLIC, 40000, DNS_PORT),
            (RESOLVER, APP, DNS_PORT, 40000),
        ] {
            let original = ipv4_tcp(source, destination, source_port, destination_port);
            for direction in [Direction::Outbound, Direction::Inbound] {
                let bytes = rewrite(original.clone(), direction, &state, now);
                assert_eq!(bytes, original, "TCP must pass through");
            }
        }
        assert_eq!(mapping_count(&state), 0);
    }

    #[test]
    fn ipv6_dns_is_left_alone() {
        let state = state();
        let now = Instant::now();
        let original = ipv6_udp(
            "fd00::2".parse().expect("valid address"),
            "2606:4700:4700::1111".parse().expect("valid address"),
            40000,
            DNS_PORT,
            b"ipv6 query",
        );
        for direction in [Direction::Outbound, Direction::Inbound] {
            let bytes = rewrite(original.clone(), direction, &state, now);
            assert_eq!(bytes, original, "IPv6 has no in-tunnel DNS redirect");
        }
        assert_eq!(mapping_count(&state), 0);
    }

    #[test]
    fn fragmented_ipv4_dns_is_left_alone() {
        let state = state();
        let now = Instant::now();
        let mut original = ipv4_udp(APP, PUBLIC, 40000, DNS_PORT, b"first fragment");
        original[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // MF, offset 0
        seal_ipv4_header(&mut original);

        let bytes = rewrite(original.clone(), Direction::Outbound, &state, now);
        assert_eq!(
            bytes, original,
            "a fragment cannot be answered by the resolver"
        );
        assert_eq!(mapping_count(&state), 0);
    }

    #[tokio::test]
    async fn the_layer_reads_the_tun_as_outbound_and_writes_it_as_inbound() {
        #[derive(Clone, Default)]
        struct MockTun {
            /// Packets handed out by `recv`, as raw bytes.
            received: Arc<Mutex<Vec<Vec<u8>>>>,
            /// Packets received by `send`, as raw bytes.
            sent: Arc<Mutex<Vec<Vec<u8>>>>,
        }

        impl IpSend for MockTun {
            fn send(&mut self, packet: Packet<Ip>) -> impl Future<Output = io::Result<()>> + Send {
                self.sent.lock().expect("sent").push(plain(packet));
                async { Ok(()) }
            }
        }

        impl IpRecv for MockTun {
            fn recv<'a>(
                &'a mut self,
                _pool: &mut PacketBufPool,
            ) -> impl Future<Output = io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a>> + Send
            {
                let queued = std::mem::take(&mut *self.received.lock().expect("received"));
                let packets: Vec<Packet<Ip>> = queued.into_iter().map(packet_from).collect();
                async move { Ok(packets.into_iter()) }
            }

            fn mtu(&self) -> MtuWatcher {
                MtuWatcher::new(1500)
            }
        }

        let inner = MockTun::default();
        inner
            .received
            .lock()
            .expect("received")
            .push(ipv4_udp(APP, PUBLIC, 40000, DNS_PORT, b"query"));
        let mut layer = DnsRedirect::new(inner.clone(), Some(RESOLVER));
        let mut pool = PacketBufPool::new(1);

        // `recv` is app → tunnel: the packet leaving the layer already points at the resolver.
        {
            let mut packets = {
                let future = layer.recv(&mut pool);
                future.await.expect("recv")
            };
            let outbound = plain(packets.next().expect("one packet"));
            assert_eq!(&outbound[16..20], &RESOLVER.octets());
        }

        // `send` is tunnel → app: the reply has to come out with the original address back.
        let reply = packet_from(ipv4_udp(RESOLVER, APP, DNS_PORT, 40000, b"answer"));
        layer.send(reply).await.expect("send");
        let sent = inner.sent.lock().expect("sent");
        assert_eq!(&sent[0][12..16], &PUBLIC.octets());
        assert_eq!(sent[0][26], 0);
        assert_eq!(sent[0][27], 0);
    }
}
