import { vpnExtension, VpnExtensionAbility } from '@kit.NetworkKit';
import { Want } from '@kit.AbilityKit';
import { commonEventManager, BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import native from 'libyanou.so';
import { RelayQuic, WireGuardKey } from '../api/MullvadApi';
import {
  VpnStatePayload, TunnelStatus, parseTunnelStats, parseTunnelStatus, VPN_STATE_EVENT
} from '../common/VpnEvents';
import {
  VpnPrefs, VpnSettings, isLocalDnsAddress, isValidDnsAddress
} from '../settings/VpnSettings';

const DOMAIN = 0x0001;
const TAG = 'YanouVpn';

/**
 * Gateway of tunnel subnet. It is the DNS server and the config service, and it is NOT
 * the address of this device: that one is assigned by the account when the device is
 * registered, and the relay drops inner packets whose source is anything else.
 */
const TUN_GATEWAY: string = '10.64.0.1';
const TUN_DNS: string = '10.64.0.1';
const TUN_MTU: number = 1420;
/**
 * Automatic-mode content blocking: one resolver, 100.64.0.0 with a bit per blocked
 * category in the last octet. The bit values are the daemon's
 * (`mullvad-daemon/src/dns.rs`), so the relay answers the same way it does for the
 * official client: ads only is 100.64.0.1, ads and trackers is 100.64.0.3.
 */
const DNS_BLOCKING_BASE: string = '100.64.0.';
const DNS_BLOCK_ADS: number = 1 << 0;
const DNS_BLOCK_TRACKERS: number = 1 << 1;
const DNS_BLOCK_MALWARE: number = 1 << 2;
const DNS_BLOCK_ADULT: number = 1 << 3;
const DNS_BLOCK_GAMBLING: number = 1 << 4;
const DNS_BLOCK_SOCIAL: number = 1 << 5;
/**
 * Ports to try against a relay, in order.
 *
 * Every Mullvad relay listens on the ranges published in the signed relay list
 * ([53], [123], [4000-33433], [33565-51820], [52001-60000]). The historic default,
 * 51820, is the one most likely to be blocked on a filtered network, so it is tried
 * first only to fail fast.
 */
const PORT_CANDIDATES: number[] = [51820, 53, 123];
/** The Shadowsocks UDP port bridges publish for `aes-256-gcm`. */
const BRIDGE_SS_PORT: number = 1236;
/** One relay gets this long to handshake before the next candidate is tried. */
const ATTEMPT_MS: number = 5000;
/** How long the ladder keeps trying before the connection is reported as failed. */
const BUDGET_MS: number = 180000;
/**
 * How long a tunnel that calls itself connected may move no traffic at all before it is
 * declared dead. WireGuard sends a keepalive every 25 s, so an idle tunnel still moves
 * datagrams; a minute and a half of complete silence means the session is gone.
 */
const STALL_MS: number = 90000;
/**
 * How old the last key exchange may get before the tunnel counts as dead. WireGuard
 * rekeys every ~2 minutes while it is moving traffic, so four minutes without one means
 * the relay stopped answering even though the engine is still sending keepalives.
 */
const HANDSHAKE_STALE_MS: number = 240000;
/** What the engine reports for "this peer has no session at all". */
const NO_HANDSHAKE_AGE_MS: number = 3600000;
/** Minimum gap between automatic rebuilds, so a flapping relay cannot spin the ladder. */
const REBUILD_GAP_MS: number = 2000;

/**
 * What the resolver preferences amount to for one VpnConfig. `summary` is for the
 * diagnostics log only.
 */
interface DnsChoice {
  /** Handed to VpnConfig.dnsAddresses, in preference order. */
  addresses: string[];
  /** Local resolvers, which must stay outside the tunnel to be reachable at all. */
  excluded: string[];
  summary: string;
}

/** Bitmask of the enabled content-blocking categories; 0 means no blocking. */
function blockingMask(prefs: VpnPrefs): number {
  let mask: number = 0;
  if (prefs.blockAds) {
    mask |= DNS_BLOCK_ADS;
  }
  if (prefs.blockTrackers) {
    mask |= DNS_BLOCK_TRACKERS;
  }
  if (prefs.blockMalware) {
    mask |= DNS_BLOCK_MALWARE;
  }
  if (prefs.blockAdult) {
    mask |= DNS_BLOCK_ADULT;
  }
  if (prefs.blockGambling) {
    mask |= DNS_BLOCK_GAMBLING;
  }
  if (prefs.blockSocial) {
    mask |= DNS_BLOCK_SOCIAL;
  }
  return mask;
}

/**
 * Resolves the DNS preferences to the addresses the system will hand to applications.
 *
 * Custom mode wins whenever it holds at least one valid address; an empty list falls
 * back to the tunnel resolver, like the daemon's `DnsState::Custom` with no address.
 * Content blocking is an auto-mode feature: its categories are bits in the resolver
 * address, so a custom resolver cannot carry them and they are ignored above.
 */
function dnsChoice(prefs: VpnPrefs): DnsChoice {
  if (prefs.dnsMode === 'custom') {
    const valid: string[] = prefs.customDns.filter((address: string) => isValidDnsAddress(address));
    if (valid.length > 0) {
      const excluded: string[] = valid.filter((address: string) => isLocalDnsAddress(address));
      return {
        addresses: valid,
        excluded: excluded,
        summary: `custom · ${valid.length} resolver(s) · ` +
          `${excluded.length} reachable outside the tunnel`
      };
    }
    return { addresses: [TUN_DNS], excluded: [], summary: 'custom with no address · default resolver' };
  }
  const mask: number = blockingMask(prefs);
  if (mask === 0) {
    return { addresses: [TUN_DNS], excluded: [], summary: `auto · no blocking · ${TUN_DNS}` };
  }
  const resolver: string = `${DNS_BLOCKING_BASE}${mask}`;
  return { addresses: [resolver], excluded: [], summary: `auto · blocking mask ${mask} · ${resolver}` };
}

/**
 * A route the system must not send into the tunnel. The daemon installs the private
 * resolvers outside the tunnel (its `DnsConfig::from_addresses(.., non_tunnel_config)`);
 * here the equivalent is an excluded route for the resolver itself.
 *
 * The exclusion is a host route per resolver, not the whole RFC1918 range: the tunnel's
 * own subnet is inside 10/8 (gateway 10.64.0.1, device address from the account), and
 * the engine's self-test probes 10.64.0.1, so excluding 10/8 as a whole would take the
 * tunnel's control traffic and its probe off the tunnel.
 */
function excludedResolverRoute(address: string): vpnExtension.RouteInfo {
  const ipv6: boolean = address.indexOf(':') >= 0;
  return {
    interface: 'vpn-tun',
    destination: {
      address: { address: address, family: ipv6 ? 2 : 1 },
      prefixLength: ipv6 ? 128 : 32
    },
    gateway: { address: ipv6 ? '::' : '0.0.0.0', family: ipv6 ? 2 : 1 },
    hasGateway: false,
    isDefaultRoute: false,
    // API 20+: the route is installed as a throw route in the VPN table, so the lookup
    // falls through to the physical network instead of the tunnel.
    isExcludedRoute: true
  };
}

/**
 * One rung of the transport ladder: which family to dial, and how the datagrams are
 * carried to the relay — plain UDP, LWO over the relay, Shadowsocks through a bridge, a
 * TCP stream with udp2tcp, or MASQUE through a QUIC proxy.
 */
interface TransportDescriptor {
  /** Stable name used in diagnostics; one transport may have one entry per family. */
  id: string;
  /** Which transport the native core builds for this attempt. */
  kind: 'direct' | 'shadowsocks' | 'lwo' | 'udp2tcp' | 'quic';
  family: 'v4' | 'v6';
  /**
   * True when the attempt hides WireGuard: Shadowsocks through a bridge, LWO over the
   * relay itself, udp2tcp inside a TCP stream, or MASQUE inside QUIC. The protocol
   * preference keeps only these in obfuscated mode.
   */
  obfuscated: boolean;
}

/**
 * LWO version a relay advertises: 2 when it speaks LWO v2, 1 when it only speaks v1, 0
 * when it does not advertise LWO at all. `lwo_v2` is a superset of `lwo`.
 */
function lwoVersionOf(candidate: RelayCandidate): number {
  if (candidate.lwoV2 === true) {
    return 2;
  }
  if (candidate.lwo === true) {
    return 1;
  }
  return 0;
}

/**
 * Transport ladder, mirroring the official client's `RETRY_ORDER`: the plain IPv6 path
 * first (the only one that survives a filtered IPv4 network), then IPv4, then LWO over
 * the relay itself, then Mullvad's Shadowsocks bridges, and finally udp2tcp — a network
 * that drops UDP may still pass TCP. The v6 rungs are skipped by `startCandidate` for a
 * relay that publishes no IPv6 address, which is the only capability udp2tcp needs.
 * Every entry is retried with a fresh port and, once the relay list is exhausted, a
 * fresh relay.
 *
 * QUIC comes last: it only exists on relays that publish `features.quic`, and QUIC on
 * 443 is the narrowest door the relays offer. The protocol preference filters this table.
 * Adding a transport is one entry here plus the code that dials it — never another branch
 * in `startCandidate`.
 */
const TRANSPORTS: TransportDescriptor[] = [
  { id: 'direct-v6', kind: 'direct', family: 'v6', obfuscated: false },
  { id: 'shadowsocks-v4', kind: 'shadowsocks', family: 'v4', obfuscated: true },
  { id: 'direct-v4', kind: 'direct', family: 'v4', obfuscated: false },
  { id: 'lwo-v4', kind: 'lwo', family: 'v4', obfuscated: true },
  { id: 'lwo-v6', kind: 'lwo', family: 'v6', obfuscated: true },
  { id: 'shadowsocks-v6', kind: 'shadowsocks', family: 'v6', obfuscated: true },
  { id: 'udp2tcp-v4', kind: 'udp2tcp', family: 'v4', obfuscated: true },
  { id: 'udp2tcp-v6', kind: 'udp2tcp', family: 'v6', obfuscated: true },
  { id: 'quic-v4', kind: 'quic', family: 'v4', obfuscated: true },
  { id: 'quic-v6', kind: 'quic', family: 'v6', obfuscated: true }
];
/** Shadowsocks ports published by the relay list (`wireguard.shadowsocks_port_ranges`). */
const SS_PORT_MIN: number = 51900;
const SS_PORT_MAX: number = 51949;
/**
 * TCP ports the relay's udp2tcp listener accepts, in the order the official client tries
 * them. Upstream hardcodes the same three (`UDP2TCP_PORTS` in `mullvad-api`'s relay
 * list); the API does not publish them, so there is nothing to read from the relay list.
 */
const UDP2TCP_PORTS: number[] = [80, 443, 5001];
/** Port of the relay's own WireGuard listener, seen from inside the obfuscated tunnel. */
const INNER_WG_PORT: number = 51820;
/**
 * Port of the MASQUE proxy: it pretends to be an ordinary HTTPS server, so it is 443 and
 * not a WireGuard port.
 */
const QUIC_PROXY_PORT: number = 443;

/** Per-transport settings the native core reads from `settings` in `tunnelStart`. */
interface Udp2TcpSettings {
  /** Relay TCP port for this udp2tcp attempt; one of UDP2TCP_PORTS. */
  port: number;
}

/** The MASQUE settings the core needs: proxy address, SNI/authority and relay token. */
interface QuicSettings {
  addr: string;
  domain: string;
  token: string;
}

/**
 * The VPN service process.
 *
 * This ability owns the tun fd: the system hands it to `VpnConnection.create`, and
 * from that point the native core is the only reader. The UI process never sees the
 * fd — it only gets counters through a common event.
 */
interface RelayCandidate {
  hostname: string;
  ip: string;
  ipv6: string;
  /** Dedicated Shadowsocks addresses published by the relay list. */
  ssExtra: string[];
  publicKey: string;
  /** LWO v1/v2 capability; absent from candidates built by an older UI. */
  lwo?: boolean;
  lwoV2?: boolean;
  /** QUIC/MASQUE proxy details; absent when the relay publishes none. */
  quic?: RelayQuic;
}

export default class YanouVpnAbility extends VpnExtensionAbility {
  private connection: vpnExtension.VpnConnection | undefined = undefined;
  private tunnelFd: number = -1;
  private relayFd: number = -1;
  private ticker: number = -1;
  private publicKey: string = '';
  private phase: string = 'idle';
  private target: string = '';
  private relayIp: string = '';
  private relayKey: string = '';
  private candidates: RelayCandidate[] = [];
  private candidateIndex: number = 0;
  private attemptStartedAt: number = 0;
  private connectStartedAt: number = 0;
  private diagnostics: boolean = false;
  private portIndex: number = 0;
  /** Position in UDP2TCP_PORTS; each udp2tcp attempt takes the next one. */
  private udp2tcpPortIndex: number = 0;
  private ticks: number = 0;
  private tunnelIpv4: string = '';
  /** Public key the account registered for this device. */
  private expectKey: string = '';
  /** "ipv4", "ipv6" or "auto": which family the engine forwards. */
  private ipVersion: string = 'ipv4';
  /** Transport ladder for this connection, chosen by the protocol preference. */
  private ladder: TransportDescriptor[] = TRANSPORTS;
  private rxBytes: number = 0;
  private txBytes: number = 0;
  /** What the attempt in flight is doing, so the UI can say more than "Connecting". */
  private transport: string = '';
  private family: string = '';
  private endpoint: string = '';
  /** Time from `tunnel: device up` to the handshake confirmation; 0 until it happens. */
  private handshakeMs: number = 0;
  /** Last activity figure seen on a live tunnel, and when it last moved. */
  private lastProgress: number = -1;
  private lastProgressAt: number = 0;
  /** Set when the supervisor has decided the tunnel is dead and a rebuild is due. */
  private rebuildPending: boolean = false;
  private rebuilds: number = 0;
  private lastRebuildAt: number = 0;
  /** Why the tunnel was declared lost; republished every tick so the UI keeps it. */
  private lostReason: string = '';

  onCreate(want: Want): void {
    hilog.info(DOMAIN, TAG, 'onCreate %{public}s', want.abilityName);
    const params: Record<string, Object> | undefined = want.parameters;
    const ipv6: string = params !== undefined && params['ipv6'] !== undefined ?
      params['ipv6'] as string : '';
    const killSwitch: boolean = params !== undefined && params['killSwitch'] !== undefined ?
      params['killSwitch'] as boolean : false;
    this.target = params !== undefined && params['target'] !== undefined ?
      params['target'] as string : '';
    this.relayIp = params !== undefined && params['relayIp'] !== undefined ?
      params['relayIp'] as string : '';
    this.relayKey = params !== undefined && params['relayKey'] !== undefined ?
      params['relayKey'] as string : '';
    this.tunnelIpv4 = params !== undefined && params['tunnelIpv4'] !== undefined ?
      params['tunnelIpv4'] as string : '';
    this.ipVersion = params !== undefined && params['ipVersion'] !== undefined ?
      params['ipVersion'] as string : 'ipv4';
    this.expectKey = params !== undefined && params['expectKey'] !== undefined ?
      params['expectKey'] as string : '';
    const diagnostics: boolean = params !== undefined && params['diagnostics'] !== undefined ?
      params['diagnostics'] as boolean : false;
    const raw: string = params !== undefined && params['relayCandidates'] !== undefined ?
      params['relayCandidates'] as string : '';
    if (raw.length > 0) {
      try {
        this.candidates = JSON.parse(raw) as RelayCandidate[];
      } catch (e) {
        hilog.error(DOMAIN, TAG, 'bad relay candidate list');
      }
    }
    hilog.info(DOMAIN, TAG, 'candidates=%{public}d target=%{public}s',
      this.candidates.length, this.target);
    this.diagnostics = diagnostics;
    this.setup(ipv6, killSwitch);
  }

  onDestroy(): void {
    hilog.info(DOMAIN, TAG, 'onDestroy');
    this.teardown();
  }

  private async setup(ipv6Cidr: string, killSwitch: boolean): Promise<void> {
    try {
      native.init(this.context.filesDir);
      // Bit 1 is IPv4, bit 2 is IPv6. The engine forwards only the selected family; the
      // other one is still routed into the tun by the system, so it is dropped there
      // instead of leaving the device unprotected.
      const families: number = this.ipVersion === 'ipv6' ? 2 : (this.ipVersion === 'auto' ? 3 : 1);
      native.setIpVersion(families);
      // Must precede the marker: logging is opt-in per process, and this process has its
      // own copy of the native library with its own flag.
      native.setDiagnostics(this.diagnostics);
      native.logMarker(`connect ${new Date().toISOString()} · ${this.target}`);
      // Read-only: the tunnel must use the key the sign-in flow registered, never a new one.
      const key = JSON.parse(native.deviceKey()) as WireGuardKey;
      this.publicKey = key.publicKey;
      hilog.info(DOMAIN, TAG, 'tunnel key %{public}s', this.publicKey.length > 0 ?
        this.publicKey.substring(0, 16) : '(none)');
      if (this.publicKey.length === 0) {
        this.fail('No device key on this tablet. Sign out and sign in again.');
        return;
      }
      if (this.expectKey.length > 0 && this.publicKey !== this.expectKey) {
        this.fail('Device key mismatch: the tunnel key is not the one the account ' +
          'registered. Sign out and sign in again.');
        return;
      }

      // The session stores the address as a CIDR ("10.170.64.72/32"); LinkAddress wants
      // the address and the prefix separately, and rejects the combined string.
      const ipv4Parts: string[] = this.tunnelIpv4.split('/');
      const tunAddress: string = ipv4Parts.length > 0 && ipv4Parts[0].length > 0 ?
        ipv4Parts[0] : TUN_GATEWAY;
      const tunPrefix: number = ipv4Parts.length > 1 ? Number.parseInt(ipv4Parts[1], 10) : 32;
      native.logLine(`tun address ${tunAddress}/${tunPrefix} · gateway ${TUN_GATEWAY}`);
      // DNS is a preference, not part of the intent: read it from the same store the
      // settings page writes, like protocolMode, so a replayed Want cannot restore an
      // old choice. The addresses are re-validated here because one malformed entry
      // makes the system reject the whole VpnConfig.
      const prefs: VpnPrefs = await VpnSettings.load(this.context);
      const dns: DnsChoice = dnsChoice(prefs);
      const addresses: vpnExtension.LinkAddress[] = [
        { address: { address: tunAddress, family: 1 }, prefixLength: tunPrefix }
      ];
      const routes: vpnExtension.RouteInfo[] = [
        {
          interface: 'vpn-tun',
          destination: { address: { address: '0.0.0.0', family: 1 }, prefixLength: 0 },
          // The gateway has to sit inside the interface's own /32, so it is the address
          // itself. 10.64.0.1 is the DNS/config-service address, not a next hop.
          gateway: { address: tunAddress, family: 1 },
          hasGateway: false,
          isDefaultRoute: true
        }
      ];
      let ipv6Address: string = '';
      if (ipv6Cidr.length > 0) {
        const parts: string[] = ipv6Cidr.split('/');
        const declared: number = parts.length > 1 ? Number.parseInt(parts[1], 10) : 128;
        // A /128 host route is rejected for the vNIC, and the system then quietly keeps the
        // interface IPv4-only. A /64 is the smallest prefix that gets the address installed.
        const prefix: number = declared < 64 ? 64 : declared;
        ipv6Address = parts[0];
        // The v6 address goes in first: the vNIC comes up IPv6-capable only when the IPv6
        // entry is present, and the earlier order made the system apply IPv4 and drop v6.
        addresses.unshift({
          address: { address: ipv6Address, family: 2 },
          prefixLength: prefix
        });
        // The address alone does not route v6 into the tunnel; ::/0 has to be claimed too.
        // The next hop is the unspecified address, not the vNIC's own /128: it is ignored
        // when `hasGateway` is false, and handing the interface its own address as a
        // gateway made the system drop this route silently, so IPv6 left the device
        // unprotected and the network reset every TLS handshake to a v6 address.
        routes.push({
          interface: 'vpn-tun',
          destination: { address: { address: '::', family: 2 }, prefixLength: 0 },
          gateway: { address: '::', family: 2 },
          hasGateway: false,
          isDefaultRoute: true
        });
        hilog.info(DOMAIN, TAG, 'ipv6 %{public}s', ipv6Cidr);
      }

      // Private resolvers cannot be reached through the relay, so their traffic has to
      // leave by the physical network even though the default route claims everything.
      for (const address of dns.excluded) {
        routes.push(excludedResolverRoute(address));
      }

      this.connection = vpnExtension.createVpnConnection(this.context);
      const config: vpnExtension.VpnConfig = {
        addresses: addresses,
        routes: routes,
        dnsAddresses: dns.addresses,
        mtu: TUN_MTU,
        isIPv4Accepted: true,
        isIPv6Accepted: ipv6Cidr.length > 0,
        // IPv4-only is a promise, not a preference: the family that is not forwarded has to
        // be blocked on the carrier too, or the system keeps routing app IPv6 around the
        // tunnel and those connections are reset by the network. Blocking mode is what
        // enforces that, so it stays on whenever a family is excluded.
        isBlocking: killSwitch || this.ipVersion !== 'auto'
      };

      this.tunnelFd = await this.connection.create(config);
      hilog.info(DOMAIN, TAG, 'tun fd=%{public}d', this.tunnelFd);
      native.logLine(`vpn config: tun fd ${this.tunnelFd} · mtu ${TUN_MTU} · ` +
        `dns ${dns.addresses.join(', ')} · ` +
        `ipv6 ${ipv6Cidr.length > 0 ? ipv6Cidr : 'off'} · families ${this.ipVersion} · ` +
        `killSwitch ${killSwitch} · ` +
        `own traffic goes through the tunnel (protect() covers the engine socket)`);
      native.logLine(`dns: ${dns.summary}` +
        (dns.excluded.length > 0 ? ` · outside the tunnel: ${dns.excluded.join(', ')}` : ''));
      native.logLine(`candidates: ${this.candidates.length} from ${this.target}`);

      if (this.candidates.length === 0 && this.relayIp.length > 0 && this.relayKey.length > 0) {
        this.candidates = [
          { hostname: this.target, ip: this.relayIp, ipv6: '', ssExtra: [], publicKey: this.relayKey }
        ];
      }

      if (this.candidates.length === 0) {
        // Nothing to connect to: the tunnel is up but holds traffic. Say so instead of
        // pretending a connection exists.
        native.attachTun(this.tunnelFd, TUN_MTU);
        this.fail('No relay selected. Pick a country or relay first.');
        return;
      }

      this.connectStartedAt = Date.now();
      this.portIndex = 0;
      this.udp2tcpPortIndex = 0;
      // Protocol preference: Automatic walks every transport, otherwise only one family.
      try {
        const mode: string = await VpnSettings.getString(this.context, 'protocolMode', 'auto');
        this.ladder = this.protocolLadder(mode);
      } catch (e) {
        this.ladder = TRANSPORTS;
      }
      native.logLine(`ladder (${this.ladder.length} transports): ` +
        `${this.ladder.map((entry: TransportDescriptor) => entry.id).join(', ')}`);
      this.phase = 'connecting';
      native.logLine('result: connecting');
      this.publish();
      this.ticker = setInterval(() => {
        this.tick();
      }, 1000);
      this.startCandidate();
    } catch (e) {
      const err = e as BusinessError;
      const message: string = `${err.code ?? -1}: ${err.message ?? 'unknown'}`;
      hilog.error(DOMAIN, TAG, 'setup failed %{public}s', message);
      this.phase = 'failed';
      native.logLine(`result: failed · setup rejected (${message})`);
      this.publish(message);
    }
  }

  /**
   * Per-transport settings the native core needs as JSON: the QUIC token and SNI, an
   * LWO version, a udp2tcp port. Empty when the transport has nothing to say.
   *
   * `port` is the port this attempt already chose, so the JSON and the endpoint the
   * attempt logs can never disagree.
   */
  private transportSettings(entry: TransportDescriptor, candidate: RelayCandidate,
    port: number): string {
    if (entry.kind === 'lwo') {
      const version: number = lwoVersionOf(candidate);
      // An empty settings string means "this entry cannot be dialled"; startCandidate
      // skips such an attempt before it opens a socket.
      return version > 0 ? `{"version":${version}}` : '';
    }
    if (entry.kind === 'udp2tcp') {
      const settings: Udp2TcpSettings = { port: port };
      return JSON.stringify(settings);
    }
    if (entry.kind === 'quic') {
      const quic: RelayQuic | undefined = candidate.quic;
      if (quic === undefined || quic === null) {
        return '';
      }
      const addr: string = this.quicAddress(quic, entry.family === 'v6');
      const domain: string = quic.domain !== undefined && quic.domain !== null ? quic.domain : '';
      const token: string = quic.token !== undefined && quic.token !== null ? quic.token : '';
      if (addr.length === 0 || domain.length === 0 || token.length === 0) {
        return '';
      }
      // The native side dials addr:443, uses domain as the TLS SNI (and the HTTP
      // authority), and puts token in the CONNECT request's Authorization header.
      const settings: QuicSettings = { addr: addr, domain: domain, token: token };
      return JSON.stringify(settings);
    }
    return '';
  }

  /**
   * The QUIC proxy address for one family, or '' when the relay publishes none.
   *
   * `features.quic.addr_in` mixes both families, and the relay's own addresses appear
   * there only when they also serve as proxy addresses, so this list is the only source
   * for the address to dial. One is picked at random, like the official relay selector
   * does, so retries spread over the addresses instead of always hitting the first.
   */
  private quicAddress(quic: RelayQuic, v6: boolean): string {
    const addresses: string[] = quic.addr !== undefined && quic.addr !== null ? quic.addr : [];
    const matching: string[] = [];
    for (const address of addresses) {
      if (address.includes(':') === v6) {
        matching.push(address);
      }
    }
    if (matching.length === 0) {
      return '';
    }
    return matching[Math.floor(Math.random() * matching.length)];
  }

  /**
   * The transports that apply to the protocol preference, in table order. Automatic keeps
   * all of them; the other modes keep one column of the table.
   */
  private protocolLadder(mode: string): TransportDescriptor[] {
    if (mode === 'direct') {
      return TRANSPORTS.filter((entry: TransportDescriptor) => !entry.obfuscated);
    }
    if (mode === 'obfuscated') {
      return TRANSPORTS.filter((entry: TransportDescriptor) => entry.obfuscated);
    }
    return TRANSPORTS;
  }

  /**
   * Walks the ladder: relay × transport × port, forever until the budget runs out.
   *
   * Each attempt gets its own protected socket, because the engine takes ownership of it
   * and closing the tunnel closes the fd.
   */
  private async startCandidate(): Promise<void> {
    while (this.candidates.length > 0) {
      if (Date.now() - this.connectStartedAt > BUDGET_MS) {
        this.fail(`No route to the relay after ${BUDGET_MS / 60000} minutes ` +
          `(${this.candidateIndex} attempts across ${this.ladder.length} transports).`);
        return;
      }
      // Ladder-major: exhaust every relay on one transport before moving to the next.
      // On a network that blackholes IPv4, the first pass over IPv6 has to be complete
      // before we spend attempts on transports that cannot possibly work.
      const count: number = this.candidates.length;
      const candidate: RelayCandidate = this.candidates[this.candidateIndex % count];
      const entry: TransportDescriptor =
        this.ladder[Math.floor(this.candidateIndex / count) % this.ladder.length];
      this.candidateIndex += 1;

      const wantsV6: boolean = entry.family === 'v6';
      const isUdp2Tcp: boolean = entry.kind === 'udp2tcp';
      const isShadowsocks: boolean = entry.kind === 'shadowsocks';
      const isQuic: boolean = entry.kind === 'quic';
      const ipv6: string = candidate.ipv6 !== undefined && candidate.ipv6 !== null ?
        candidate.ipv6 : '';
      // A relay without its own IPv6 address has nothing to dial over v6. QUIC is the
      // exception: it dials a proxy address the relay publishes, not the relay's own.
      if (wantsV6 && ipv6.length === 0 && !isQuic) {
        continue;
      }
      // LWO is only dialled when the relay advertises it. Skipping the rung costs one
      // candidate slot instead of a five-second attempt that cannot work.
      const lwoVersion: number = entry.kind === 'lwo' ? lwoVersionOf(candidate) : 0;
      if (entry.kind === 'lwo' && lwoVersion === 0) {
        continue;
      }
      // QUIC dials a proxy address the relay publishes, and only has one when it carries
      // `features.quic`. A rung that does not apply to this relay is skipped, which is
      // what keeps the other transports working unchanged.
      const quic: RelayQuic | undefined = candidate.quic;
      let quicAddr: string = '';
      if (isQuic) {
        if (quic === undefined || quic === null) {
          continue;
        }
        quicAddr = this.quicAddress(quic, wantsV6);
        if (quicAddr.length === 0) {
          continue;
        }
      }
      const endpointIp: string = isQuic ? quicAddr : (wantsV6 ? ipv6 : candidate.ip);
      const family: number = wantsV6 ? 6 : 4;
      // Each transport has its own port: the proxy's HTTPS port for QUIC, udp2tcp's three
      // TCP ports, the bridge's Shadowsocks range, or the published WireGuard UDP ranges.
      const port: number = isQuic ? QUIC_PROXY_PORT :
        (isUdp2Tcp ? this.nextUdp2TcpPort() :
          (isShadowsocks ? this.nextShadowsocksPort() : this.nextPort()));
      // Shadowsocks goes to a dedicated address when the relay publishes one; the relay's
      // own address is the one that gets blackholed. udp2tcp has no such list: the relay
      // itself listens for it, so it must use the relay's own address.
      const extra: string[] = candidate.ssExtra !== undefined && candidate.ssExtra !== null ?
        candidate.ssExtra : [];
      const host: string = isShadowsocks && extra.length > 0 ?
        extra[Math.floor(Math.random() * extra.length)] : endpointIp;
      const hostPort: string = host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
      const bridge: string = isShadowsocks ? hostPort : '';
      const settings: string = this.transportSettings(entry, candidate, port);
      if (isQuic && settings.length === 0) {
        // A relay that publishes `features.quic` without a usable token, SNI or address is
        // a broken entry, not a network problem: skip it instead of spending an attempt.
        continue;
      }

      this.target = candidate.hostname;
      // Record what this attempt is before dialling, so a payload published mid-attempt
      // never describes the previous candidate.
      this.transport = entry.kind;
      this.family = wantsV6 ? 'ipv6' : 'ipv4';
      this.endpoint = hostPort;
      this.handshakeMs = 0;
      this.attemptStartedAt = Date.now();

      // udp2tcp rides a TCP stream and needs a TCP socket; every other transport sends
      // datagrams from a UDP socket. Either way the extension protects the fd it opened,
      // and the core claims the matching slot by transport name.
      const proto: string = isUdp2Tcp ? 'tcp' : 'udp';
      const relayFd: number = native.openRelaySocket(family, proto);
      this.relayFd = relayFd;
      if (relayFd >= 0 && this.connection !== undefined) {
        try {
          await this.connection.protect(relayFd);
        } catch (e) {
          const err = e as BusinessError;
          native.logLine(`protect fd ${relayFd} failed: ${err.code ?? -1}`);
        }
      } else {
        native.logLine(`relay socket not available (${relayFd})`);
      }

      // Shadowsocks and udp2tcp deliver to the relay's own loopback listener on 51820;
      // LWO wraps the datagrams in place and QUIC dials the proxy, so both keep the port
      // they actually dial.
      const wireguardPort: number = (isShadowsocks || isUdp2Tcp) ? INNER_WG_PORT : port;
      const started = JSON.parse(native.tunnelStart(this.tunnelFd, TUN_MTU, candidate.publicKey,
        endpointIp, wireguardPort, bridge, entry.kind, settings)) as Record<string, Object>;
      hilog.info(DOMAIN, TAG, 'attempt %{public}s %{public}s', candidate.hostname,
        JSON.stringify(started));
      const route: string = isShadowsocks ? `shadowsocks via ${host}` :
        (isUdp2Tcp ? 'udp2tcp' :
          (isQuic ? `quic via ${quicAddr}` :
            (entry.kind === 'lwo' ? `lwo v${lwoVersion}` : 'direct')));
      native.logLine(`attempt ${this.candidateIndex}: ${candidate.hostname} ` +
        `${hostPort} ipv${family} ${route}`);
      if (started['ok'] === true) {
        return;
      }
      const reason: string = started['error'] !== undefined ? started['error'] as string : 'unknown';
      native.logLine(`engine refused this attempt: ${reason}`);
      await this.delay(100);
    }
    this.fail('No relay selected.');
  }

  private nextShadowsocksPort(): number {
    return SS_PORT_MIN + Math.floor(Math.random() * (SS_PORT_MAX - SS_PORT_MIN + 1));
  }

  /**
   * 80, 443, 5001, then around again: the relay's udp2tcp listener publishes no ports in
   * the API, so these are the three the official client cycles through.
   */
  private nextUdp2TcpPort(): number {
    const port: number = UDP2TCP_PORTS[this.udp2tcpPortIndex % UDP2TCP_PORTS.length];
    this.udp2tcpPortIndex += 1;
    return port;
  }

  /**
   * 51820 first, then the famous ports that get through filters (53, 123), then a random
   * port inside the published ranges so a port-based block is not the end of the story.
   */
  private nextPort(): number {
    if (this.portIndex < PORT_CANDIDATES.length) {
      const port: number = PORT_CANDIDATES[this.portIndex];
      this.portIndex += 1;
      return port;
    }
    this.portIndex += 1;
    const ranges: number[][] = [[4000, 33433], [33565, 51819], [52001, 60000]];
    const range: number[] = ranges[Math.floor(Math.random() * ranges.length)];
    return range[0] + Math.floor(Math.random() * (range[1] - range[0] + 1));
  }

  private delay(milliseconds: number): Promise<void> {
    return new Promise<void>((resolve: (value: void) => void) => {
      setTimeout(() => {
        resolve();
      }, milliseconds);
    });
  }

  private tick(): void {
    // Heartbeat: proves from hilog whether this process keeps running while the app is
    // in the background, which is what decides if the tunnel survives.
    this.ticks += 1;
    if (this.ticks % 30 === 0) {
      hilog.info(DOMAIN, TAG, 'alive phase=%{public}s ticks=%{public}d', this.phase, this.ticks);
    }
    if (this.phase === 'connecting') {
      const status: TunnelStatus = parseTunnelStatus(native.tunnelStatus());
      this.rxBytes = status.rxBytes;
      this.txBytes = status.txBytes;
      if (status.handshake) {
        // The engine only reports a boolean, so the ladder's own clock is the best
        // measurement available: attempt start to the first "handshake" tick.
        this.handshakeMs = Math.max(0, Date.now() - this.attemptStartedAt);
        hilog.info(DOMAIN, TAG, 'handshake confirmed after %{public}d ms', this.handshakeMs);
        native.logLine(`result: connected (${this.target})`);
        this.phase = 'connected';
        // A fresh session starts the stall clock from now, not from the last one.
        this.lastProgress = -1;
        this.lastProgressAt = Date.now();
        this.publish();
      } else if (Date.now() - this.connectStartedAt > BUDGET_MS) {
        this.fail(`${this.target} did not complete a handshake within ` +
          `${BUDGET_MS / 1000} s.`);
        return;
      } else if (status.error.length > 0 || Date.now() - this.attemptStartedAt > ATTEMPT_MS) {
        native.logLine(`relay ${this.target}: sent ${status.udpSent} datagrams, received ` +
          `${status.udpRecv}${status.error.length > 0 ? ` · ${status.error}` : ''}`);
        native.logLine(`relay ${this.target} did not answer, trying the next one`);
        native.tunnelStop();
        this.startCandidate();
      }
    } else if (this.phase === 'connected') {
      // Nothing used to watch a live tunnel, so a dead one kept reporting "connected"
      // and the user only found out when a page refused to load.
      this.supervise();
    } else if (this.phase === 'lost' && this.rebuildPending) {
      this.rebuildPending = false;
      this.rebuild();
    }
    this.publish(this.phase === 'lost' ? this.lostReason : '');
  }

  /**
   * Watches a live tunnel. WireGuard sends a keepalive every 25 s and the engine counts
   * every datagram it moves, so a session that stops moving is gone even while the
   * process, the tun fd and the UI all still look perfectly healthy.
   */
  private supervise(): void {
    const status: TunnelStatus = parseTunnelStatus(native.tunnelStatus());
    this.rxBytes = status.rxBytes;
    this.txBytes = status.txBytes;
    const now: number = Date.now();
    if (this.ticks % 60 === 0) {
      hilog.info(DOMAIN, TAG, 'tunnel health: last key exchange %{public}d s ago',
        Math.round(status.handshakeAgeMs / 1000));
    }
    if (status.handshakeAgeMs >= HANDSHAKE_STALE_MS) {
      // The engine keeps sending keepalives into a dead relay, so the byte counters still
      // move; only the age of the last key exchange separates that from a healthy tunnel.
      // The engine reports the sentinel when the peer has no session left at all.
      this.markLost(status.handshakeAgeMs >= NO_HANDSHAKE_AGE_MS ?
        'the relay session expired' :
        `No key exchange with the relay for ${Math.round(status.handshakeAgeMs / 1000)} s`);
      return;
    }
    const progress: number = status.udpSent + status.udpRecv + status.rxBytes + status.txBytes;
    if (progress !== this.lastProgress) {
      this.lastProgress = progress;
      this.lastProgressAt = now;
      return;
    }
    if (this.lastProgressAt === 0) {
      this.lastProgressAt = now;
      return;
    }
    if (now - this.lastProgressAt >= STALL_MS) {
      this.markLost(`No traffic through the tunnel for ${Math.round(STALL_MS / 1000)} s`);
    }
  }

  /** Declares a connected tunnel dead and schedules a rebuild on the next tick. */
  private markLost(reason: string): void {
    const now: number = Date.now();
    if (this.phase !== 'connected' || now - this.lastRebuildAt < REBUILD_GAP_MS) {
      return;
    }
    this.lastRebuildAt = now;
    this.rebuilds += 1;
    hilog.warn(DOMAIN, TAG, 'tunnel dropped: %{public}s', reason);
    native.logLine(`result: lost · ${reason} · rebuild #${this.rebuilds}`);
    this.lostReason = reason;
    this.lastProgress = -1;
    this.lastProgressAt = 0;
    this.phase = 'lost';
    // Stop the dead engine now, but rebuild on the next tick: the UI and the notification
    // then have a full second to show what happened before the ladder starts again.
    native.tunnelStop();
    this.rebuildPending = true;
  }

  /** Re-dials the ladder on the tun this ability still owns, without asking the user. */
  private rebuild(): void {
    if (this.connection === undefined) {
      return;
    }
    hilog.info(DOMAIN, TAG, 'rebuilding tunnel (#%{public}d)', this.rebuilds);
    native.logLine(`rebuild #${this.rebuilds}: re-dialling the ladder`);
    this.phase = 'connecting';
    this.connectStartedAt = Date.now();
    this.attemptStartedAt = Date.now();
    this.handshakeMs = 0;
    this.lostReason = '';
    this.publish();
    this.startCandidate();
  }

  /** Ends the attempt and releases the system VPN so the next Connect can start clean. */
  private fail(message: string): void {
    this.phase = 'failed';
    native.tunnelStop();
    native.logLine(`result: failed · ${message}`);
    this.publish(message);
    this.connection?.destroy().then(() => {
      hilog.info(DOMAIN, TAG, 'connection released after failure');
    }).catch((err: BusinessError) => {
      hilog.warn(DOMAIN, TAG, 'destroy after failure: %{public}d', err.code);
    });
    this.connection = undefined;
  }

  private publish(error: string = ''): void {
    const stats = parseTunnelStats(native.stats());
    const payload: VpnStatePayload = {
      connected: this.phase === 'connected',
      phase: this.phase,
      packets: stats.packets,
      bytes: stats.bytes,
      rxBytes: this.rxBytes,
      txBytes: this.txBytes,
      protectedFd: stats.protectedFd,
      uptimeMs: stats.uptimeMs,
      error: error,
      target: this.target,
      publicKey: this.publicKey,
      attempt: this.candidateIndex,
      transport: this.transport,
      family: this.family,
      endpoint: this.endpoint,
      handshakeMs: this.handshakeMs
    };
    const options: commonEventManager.CommonEventPublishData = {
      data: JSON.stringify(payload)
    };
    commonEventManager.publish(VPN_STATE_EVENT, options, (err: BusinessError) => {
      if (err) {
        hilog.warn(DOMAIN, TAG, 'publish failed %{public}d', err.code);
      }
    });
  }

  private teardown(): void {
    if (this.ticker >= 0) {
      clearInterval(this.ticker);
      this.ticker = -1;
    }
    native.logLine(`result: stopped (${this.phase})`);
    this.candidates = [];
    this.candidateIndex = 0;
    this.rebuildPending = false;
    this.lastProgress = -1;
    this.lastProgressAt = 0;
    this.lostReason = '';
    // Nothing is dialled any more; an idle payload must not describe the last attempt.
    this.transport = '';
    this.family = '';
    this.endpoint = '';
    this.handshakeMs = 0;
    this.phase = 'idle';
    native.tunnelStop();
    native.stop();
    this.connection?.destroy().then(() => {
      hilog.info(DOMAIN, TAG, 'connection destroyed');
    }).catch((err: BusinessError) => {
      hilog.error(DOMAIN, TAG, 'destroy failed %{public}d', err.code);
    });
    this.connection = undefined;
    this.publish();
  }
}
