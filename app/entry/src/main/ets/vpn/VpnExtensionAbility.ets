import { vpnExtension, VpnExtensionAbility } from '@kit.NetworkKit';
import { Want } from '@kit.AbilityKit';
import { commonEventManager, BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import native from 'libmuharmony.so';
import { WireGuardKey } from '../api/MullvadApi';
import {
  VpnStatePayload, TunnelStatus, parseTunnelStats, parseTunnelStatus, VPN_STATE_EVENT
} from '../common/VpnEvents';
import { VpnSettings } from '../settings/VpnSettings';

const DOMAIN = 0x0001;
const TAG = 'MuHarmonyVpn';

/**
 * Gateway of tunnel subnet. It is the DNS server and the config service, and it is NOT
 * the address of this device: that one is assigned by the account when the device is
 * registered, and the relay drops inner packets whose source is anything else.
 */
const TUN_GATEWAY: string = '10.64.0.1';
const TUN_DNS: string = '10.64.0.1';
const TUN_MTU: number = 1420;
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
 * Transport ladder, mirroring the official client's `RETRY_ORDER`: the plain IPv6 path
 * first (the only one that survives a filtered IPv4 network), then IPv4, then the same
 * two families through Mullvad's Shadowsocks obfuscation. Every entry is retried with a
 * fresh port and, once the relay list is exhausted, a fresh relay.
 */
const LADDER: string[] = ['direct-v6', 'shadowsocks-v4', 'direct-v4', 'shadowsocks-v6'];
/** The same ladder restricted to one transport family, for the protocol preference. */
const LADDER_DIRECT: string[] = ['direct-v6', 'direct-v4'];
const LADDER_OBFUSCATED: string[] = ['shadowsocks-v4', 'shadowsocks-v6'];
/** Shadowsocks ports published by the relay list (`wireguard.shadowsocks_port_ranges`). */
const SS_PORT_MIN: number = 51900;
const SS_PORT_MAX: number = 51949;
/** Port of the relay's own WireGuard listener, seen from inside the obfuscated tunnel. */
const SS_INNER_PORT: number = 51820;

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
}

export default class MuharmonyVpnAbility extends VpnExtensionAbility {
  private connection: vpnExtension.VpnConnection | undefined = undefined;
  private tunnelFd: number = -1;
  private udpFd: number = -1;
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
  private ticks: number = 0;
  private tunnelIpv4: string = '';
  /** Public key the account registered for this device. */
  private expectKey: string = '';
  /** Transport ladder for this connection, chosen by the protocol preference. */
  private ladder: string[] = LADDER;
  private rxBytes: number = 0;
  private txBytes: number = 0;
  /** What the attempt in flight is doing, so the UI can say more than "Connecting". */
  private transport: string = '';
  private family: string = '';
  private endpoint: string = '';
  /** Time from `tunnel: device up` to the handshake confirmation; 0 until it happens. */
  private handshakeMs: number = 0;

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
        const prefix: number = parts.length > 1 ? Number.parseInt(parts[1], 10) : 128;
        ipv6Address = parts[0];
        addresses.push({
          address: { address: ipv6Address, family: 2 },
          prefixLength: prefix
        });
        // The address alone does not route v6 into the tunnel; ::/0 has to be claimed too.
        routes.push({
          interface: 'vpn-tun',
          destination: { address: { address: '::', family: 2 }, prefixLength: 0 },
          gateway: { address: ipv6Address, family: 2 },
          hasGateway: false,
          isDefaultRoute: true
        });
        hilog.info(DOMAIN, TAG, 'ipv6 %{public}s', ipv6Cidr);
      }

      this.connection = vpnExtension.createVpnConnection(this.context);
      const config: vpnExtension.VpnConfig = {
        addresses: addresses,
        routes: routes,
        dnsAddresses: [TUN_DNS],
        mtu: TUN_MTU,
        isIPv4Accepted: true,
        isIPv6Accepted: ipv6Cidr.length > 0,
        isBlocking: killSwitch
      };

      this.tunnelFd = await this.connection.create(config);
      hilog.info(DOMAIN, TAG, 'tun fd=%{public}d', this.tunnelFd);
      native.logLine(`vpn config: tun fd ${this.tunnelFd} · mtu ${TUN_MTU} · dns ${TUN_DNS} · ` +
        `ipv6 ${ipv6Cidr.length > 0 ? ipv6Cidr : 'off'} · killSwitch ${killSwitch} · ` +
        `own traffic goes through the tunnel (protect() covers the engine socket)`);
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
      // Protocol preference: Automatic walks every transport, otherwise only one family.
      try {
        const mode: string = await VpnSettings.getString(this.context, 'protocolMode', 'auto');
        this.ladder = mode === 'direct' ? LADDER_DIRECT :
          (mode === 'obfuscated' ? LADDER_OBFUSCATED : LADDER);
      } catch (e) {
        this.ladder = LADDER;
      }
      native.logLine(`ladder (${this.ladder.length} transports): ${this.ladder.join(', ')}`);
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
      const entry: string = this.ladder[Math.floor(this.candidateIndex / count) % this.ladder.length];
      this.candidateIndex += 1;

      const wantsV6: boolean = entry.endsWith('-v6');
      const obfuscated: boolean = entry.startsWith('shadowsocks');
      const ipv6: string = candidate.ipv6 !== undefined && candidate.ipv6 !== null ?
        candidate.ipv6 : '';
      if (wantsV6 && ipv6.length === 0) {
        continue;
      }
      const endpointIp: string = wantsV6 ? ipv6 : candidate.ip;
      const family: number = wantsV6 ? 6 : 4;
      const port: number = obfuscated ? this.nextShadowsocksPort() : this.nextPort();
      // Shadowsocks goes to a dedicated address when the relay publishes one; the relay's
      // own address is the one that gets blackholed.
      const extra: string[] = candidate.ssExtra !== undefined && candidate.ssExtra !== null ?
        candidate.ssExtra : [];
      const ssHost: string = extra.length > 0 ? extra[Math.floor(Math.random() * extra.length)] :
        endpointIp;
      const hostPort: string = ssHost.includes(':') ? `[${ssHost}]:${port}` : `${ssHost}:${port}`;
      const bridge: string = obfuscated ? hostPort : '';

      this.target = candidate.hostname;
      // Record what this attempt is before dialling, so a payload published mid-attempt
      // never describes the previous candidate.
      this.transport = obfuscated ? 'shadowsocks' : 'direct';
      this.family = wantsV6 ? 'ipv6' : 'ipv4';
      this.endpoint = hostPort;
      this.handshakeMs = 0;
      this.attemptStartedAt = Date.now();

      const udpFd: number = native.openRelaySocket(family);
      this.udpFd = udpFd;
      if (udpFd >= 0 && this.connection !== undefined) {
        try {
          await this.connection.protect(udpFd);
        } catch (e) {
          const err = e as BusinessError;
          native.logLine(`protect fd ${udpFd} failed: ${err.code ?? -1}`);
        }
      } else {
        native.logLine(`relay socket not available (${udpFd})`);
      }

      const wireguardPort: number = obfuscated ? SS_INNER_PORT : port;
      const started = JSON.parse(native.tunnelStart(this.tunnelFd, TUN_MTU, candidate.publicKey,
        endpointIp, wireguardPort, bridge)) as Record<string, Object>;
      hilog.info(DOMAIN, TAG, 'attempt %{public}s %{public}s', candidate.hostname,
        JSON.stringify(started));
      native.logLine(`attempt ${this.candidateIndex}: ${candidate.hostname} ` +
        `${endpointIp}:${port} ipv${family} ` +
        `${obfuscated ? `shadowsocks via ${ssHost}` : 'direct'}`);
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
    }
    this.publish();
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
