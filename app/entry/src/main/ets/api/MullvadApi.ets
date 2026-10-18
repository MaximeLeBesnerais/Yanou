import native from 'libmuharmony.so';
import { fileIo as fs } from '@kit.CoreFileKit';

/**
 * Mullvad API, through the native client.
 *
 * The calls are not made with `@ohos.net.http`: on a network that poisons
 * `api.mullvad.net` the only way in is Mullvad's domain-fronting tunnel, which the Rust
 * core implements (direct TLS first, fronted through CDN77 when that fails). These
 * functions parse the JSON that comes back from that client.
 */
export interface AccessTokenResponse {
  access_token: string;
  expiry: string;
}

export interface AccountData {
  id: string;
  expiry: string;
}

export interface DeviceResponse {
  id: string;
  name: string;
  pubkey: string;
  ipv4_address: string;
  ipv6_address: string;
  hijack_dns: boolean;
  created: string;
}

export interface WireGuardKey {
  publicKey: string;
}

/** One relay, flattened by the native side so the UI never walks the raw list. */
export interface RelayItem {
  hostname: string;
  ipv4: string;
  /** Present for every relay, and the only address that works on a filtered IPv4 network. */
  ipv6: string;
  /** Dedicated Shadowsocks addresses; empty when the relay publishes none. */
  ssExtra: string[];
  publicKey: string;
  location: string;
  city: string;
  country: string;
  active: boolean;
  owned: boolean;
  daita: boolean;
}

export interface RelaySelection {
  /** "relay" for a specific host, "country" to let the client pick any relay there. */
  kind: string;
  hostname: string;
  ipv4: string;
  publicKey: string;
  city: string;
  country: string;
}

export interface Session {
  account: string;
  token: string;
  expiry: string;
  deviceId: string;
  deviceName: string;
  ipv4: string;
  ipv6: string;
  publicKey: string;
}

export const ERR_INVALID_ACCOUNT: string = 'INVALID_ACCOUNT';
export const ERR_MAX_DEVICES: string = 'MAX_DEVICES_REACHED';
export const ERR_PUBKEY_IN_USE: string = 'PUBKEY_IN_USE';
export const ERR_INVALID_TOKEN: string = 'INVALID_ACCESS_TOKEN';

export class ApiError extends Error {
  status: number;
  code: string;
  detail: string;
  /** Present when the token was obtained but device creation failed (device limit). */
  token: string;

  constructor(status: number, code: string, detail: string, token: string) {
    super(`${code.length > 0 ? code : 'API'}: ${detail}`);
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.token = token;
  }
}

interface LoginResponse {
  ok: boolean;
  session?: Session;
  code?: string;
  error?: string;
  token?: string;
  status?: number;
}

interface DevicesResponse {
  ok: boolean;
  devices?: DeviceResponse[];
  code?: string;
  error?: string;
  status?: number;
}

interface AccountResponse {
  ok: boolean;
  account?: AccountData;
  code?: string;
  error?: string;
  status?: number;
}

interface SimpleResponse {
  ok: boolean;
  code?: string;
  error?: string;
  status?: number;
}

/**
 * Signs in and reuses the device registered for this key, if any.
 * Throws `ApiError`; on `MAX_DEVICES_REACHED` its `token` lets the caller list devices.
 */
export async function login(accountNumber: string, publicKey: string): Promise<Session> {
  const parsed = JSON.parse(await native.apiLogin(accountNumber, publicKey)) as LoginResponse;
  if (parsed.ok && parsed.session !== undefined) {
    return parsed.session;
  }
  throw new ApiError(parsed.status ?? 0, parsed.code ?? '', parsed.error ?? 'login failed',
    parsed.token ?? '');
}

export async function devicesForToken(token: string): Promise<DeviceResponse[]> {
  const parsed = JSON.parse(await native.apiDevices(token)) as DevicesResponse;
  if (parsed.ok && parsed.devices !== undefined) {
    return parsed.devices;
  }
  throw new ApiError(parsed.status ?? 0, parsed.code ?? '', parsed.error ?? 'device list failed', '');
}

export async function deleteDevice(token: string, deviceId: string): Promise<void> {
  const parsed = JSON.parse(await native.apiRemoveDevice(token, deviceId)) as SimpleResponse;
  if (!parsed.ok) {
    throw new ApiError(parsed.status ?? 0, parsed.code ?? '', parsed.error ?? 'remove failed', '');
  }
}

export async function accountData(token: string): Promise<AccountData> {
  const parsed = JSON.parse(await native.apiAccount(token)) as AccountResponse;
  if (parsed.ok && parsed.account !== undefined) {
    return parsed.account;
  }
  throw new ApiError(parsed.status ?? 0, parsed.code ?? '', parsed.error ?? 'account data failed', '');
}

/** True when the token is inside `marginMs` of expiry and must be re-requested. */
export function tokenExpiring(expiry: string, marginMs: number): boolean {
  const at: number = Date.parse(expiry);
  if (isNaN(at)) {
    return false;
  }
  return at - Date.now() <= marginMs;
}

interface RelayResponse {
  ok: boolean;
  path?: string;
  count?: number;
  code?: string;
  error?: string;
}

/**
 * Fetches the relay list (native side walks the transparency log and writes a flattened
 * copy), then reads that file. The list is ~150 relays, too large for a NAPI string return.
 */
export async function fetchRelays(): Promise<RelayItem[]> {
  const parsed = JSON.parse(await native.apiRelays()) as RelayResponse;
  if (!parsed.ok || parsed.path === undefined) {
    throw new ApiError(0, parsed.code ?? '', parsed.error ?? 'relay list failed', '');
  }
  const text: string = fs.readTextSync(parsed.path);
  const list = JSON.parse(text) as Record<string, RelayItem[]>;
  return list['relays'];
}
