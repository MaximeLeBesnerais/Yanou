/**
 * Wire format shared by the VPN extension process and the UI process.
 *
 * The two live in different processes, so state travels as an in-app common event
 * rather than through shared memory. Keep this file free of platform imports: both
 * sides parse the same shape.
 */

export const VPN_STATE_EVENT: string = 'com.maxime.muharmony.VPN_STATE';

/** What the native core reports about the tunnel it is reading. */
export interface TunnelStats {
  packets: number;
  bytes: number;
  protectedFd: number;
  uptimeMs: number;
}

/** What the VPN extension publishes after every state change and every tick. */
export interface VpnStatePayload {
  connected: boolean;
  /** idle | connecting | connected | failed. `connected` is only true once a handshake exists. */
  phase: string;
  packets: number;
  bytes: number;
  /** Bytes the WireGuard peer actually received / sent, when the engine is running. */
  rxBytes: number;
  txBytes: number;
  protectedFd: number;
  uptimeMs: number;
  error: string;
  /** What the tunnel is pointed at: relay hostname, or "country · automatic". */
  target: string;
  /** Public key the tunnel process actually loaded, so the UI can spot a key mismatch. */
  publicKey: string;
  /** Attempt number in flight, 1-based, exactly as the extension numbers the ladder. */
  attempt: number;
  /** Transport of the attempt in flight: "direct" or "shadowsocks". */
  transport: string;
  /** Address family of the attempt in flight: "ipv4" or "ipv6". */
  family: string;
  /** "host:port" the tunnel is dialling, for the attempt in flight. */
  endpoint: string;
  /** Milliseconds from "device up" to the handshake, 0 while unknown. */
  handshakeMs: number;
}

export function parseVpnState(raw: string): VpnStatePayload | null {
  if (raw.length === 0) {
    return null;
  }
  try {
    return JSON.parse(raw) as VpnStatePayload;
  } catch (e) {
    return null;
  }
}

export function parseTunnelStats(raw: string): TunnelStats {
  const fallback: TunnelStats = { packets: 0, bytes: 0, protectedFd: -1, uptimeMs: 0 };
  if (raw.length === 0) {
    return fallback;
  }
  try {
    return JSON.parse(raw) as TunnelStats;
  } catch (e) {
    return fallback;
  }
}

/** What the native engine reports about the running tunnel. */
export interface TunnelStatus {
  running: boolean;
  /** A WireGuard handshake with the relay completed. */
  handshake: boolean;
  /** Kept for older builds: same as `handshake` now that peers report their session. */
  inbound: boolean;
  rxBytes: number;
  txBytes: number;
  /** Datagrams the engine actually wrote / read on the relay socket. */
  udpSent: number;
  udpRecv: number;
  error: string;
}

export function parseTunnelStatus(raw: string): TunnelStatus {
  const fallback: TunnelStatus = {
    running: false, handshake: false, inbound: false, rxBytes: 0, txBytes: 0,
    udpSent: 0, udpRecv: 0, error: ''
  };
  if (raw.length === 0) {
    return fallback;
  }
  try {
    return JSON.parse(raw) as TunnelStatus;
  } catch (e) {
    return fallback;
  }
}
