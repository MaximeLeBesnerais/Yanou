import { preferences } from '@kit.ArkData';
import { common } from '@kit.AbilityKit';

/** Where the tunnel gets its resolvers: its own gateway, or the user's list. */
export type DnsMode = 'auto' | 'custom';

/** Tunnel options that belong to the user, not to the account. */
export interface VpnPrefs {
  killSwitch: boolean;
  /**
   * Which address family the tunnel carries: "ipv4", "ipv6" or "auto" for both. The other
   * family is still routed into the tunnel but the engine drops it, so it fails fast
   * instead of escaping unprotected.
   */
  ipVersion: string;
  multihop: boolean;
  dnsBlocking: boolean;
  /** Allow the unfronted API path. Off keeps api.mullvad.net out of DNS and SNI. */
  directAllowed: boolean;
  /** Restrict relays and the tunnel to DAITA-capable ones. */
  daita: boolean;
  /**
   * DNS resolver selection. "custom" puts `customDns` into VpnConfig.dnsAddresses;
   * "auto" keeps the tunnel resolver, whose address encodes content blocking.
   */
  dnsMode: DnsMode;
  /** User-supplied resolvers, in the order they were added. Stored as a JSON array. */
  customDns: string[];
  // Content blocking only works in auto mode: the categories are bits in the resolver
  // address, and a custom resolver cannot carry them.
  blockAds: boolean;
  blockTrackers: boolean;
  blockMalware: boolean;
  blockAdult: boolean;
  blockGambling: boolean;
  blockSocial: boolean;
}

export const DEFAULT_PREFS: VpnPrefs = {
  killSwitch: false,
  // IPv4 first: a device whose IPv6 path is filtered would otherwise hang on every
  // dual-stack name for seconds before falling back.
  ipVersion: 'ipv4',
  multihop: false,
  dnsBlocking: false,
  directAllowed: false,
  daita: false,
  dnsMode: 'auto',
  customDns: [],
  blockAds: false,
  blockTrackers: false,
  blockMalware: false,
  blockAdult: false,
  blockGambling: false,
  blockSocial: false
};

const STORE_NAME: string = 'muharmony-settings';

/** A stored mode that is neither of the two is treated as the default. */
export function normalizeDnsMode(value: string): DnsMode {
  return value === 'custom' ? 'custom' : 'auto';
}

/** Trims the field and drops the brackets some sites show around IPv6 literals. */
export function normalizeDnsAddress(raw: string): string {
  let value: string = raw.trim();
  if (value.length > 2 && value.charAt(0) === '[' &&
    value.charAt(value.length - 1) === ']') {
    value = value.substring(1, value.length - 1);
  }
  return value;
}

/**
 * Dotted-quad IPv4, without the leading-zero forms that are ambiguous between decimal
 * and octal.
 */
function isIpv4(value: string): boolean {
  const parts: string[] = value.split('.');
  if (parts.length !== 4) {
    return false;
  }
  for (const part of parts) {
    if (part.length === 0 || part.length > 3) {
      return false;
    }
    if (part.length > 1 && part.charAt(0) === '0') {
      return false;
    }
    for (let index: number = 0; index < part.length; index += 1) {
      const code: number = part.charCodeAt(index);
      if (code < 48 || code > 57) {
        return false;
      }
    }
    if (Number.parseInt(part, 10) > 255) {
      return false;
    }
  }
  return true;
}

/**
 * Counts the 16-bit groups on one side of a "::", or -1 when the side is malformed.
 * A trailing dotted-quad counts as two groups and is only allowed at the very end of
 * the address.
 */
function ipv6Groups(text: string, allowIpv4: boolean): number {
  if (text.length === 0) {
    return 0;
  }
  const groups: string[] = text.split(':');
  let count: number = 0;
  for (let index: number = 0; index < groups.length; index += 1) {
    const group: string = groups[index];
    if (group.length === 0) {
      return -1;
    }
    if (index === groups.length - 1 && group.indexOf('.') >= 0 && allowIpv4) {
      if (!isIpv4(group)) {
        return -1;
      }
      count += 2;
      continue;
    }
    if (group.length > 4) {
      return -1;
    }
    const lower: string = group.toLowerCase();
    for (let digit: number = 0; digit < lower.length; digit += 1) {
      const code: number = lower.charCodeAt(digit);
      const decimal: boolean = code >= 48 && code <= 57;
      const hex: boolean = code >= 97 && code <= 102;
      if (!decimal && !hex) {
        return -1;
      }
    }
    count += 1;
  }
  return count;
}

/** Full IPv6 literal, including compressed forms and a trailing IPv4 part. */
function isIpv6(value: string): boolean {
  if (value.length === 0 || value.indexOf('%') >= 0) {
    return false;
  }
  const compressed: number = value.indexOf('::');
  if (compressed >= 0 && value.indexOf('::', compressed + 1) >= 0) {
    return false;
  }
  if (compressed < 0) {
    return ipv6Groups(value, true) === 8;
  }
  const left: number = ipv6Groups(value.substring(0, compressed), false);
  const right: number = ipv6Groups(value.substring(compressed + 2), true);
  if (left < 0 || right < 0) {
    return false;
  }
  // "::" stands for at least one zero group; eight explicit groups plus one is invalid.
  return left + right < 8;
}

/**
 * True when `value` is a bare IPv4 or IPv6 literal, which is what
 * VpnConfig.dnsAddresses accepts: no prefix length, port, brackets or zone id.
 */
export function isValidDnsAddress(value: string): boolean {
  return isIpv4(value) || isIpv6(value);
}

/** RFC1918, link-local and loopback: not reachable through the relay. */
function isPrivateIpv4(value: string): boolean {
  const parts: string[] = value.split('.');
  const first: number = Number.parseInt(parts[0], 10);
  const second: number = Number.parseInt(parts[1], 10);
  if (first === 10 || first === 127) {
    return true;
  }
  if (first === 172 && second >= 16 && second <= 31) {
    return true;
  }
  if (first === 192 && second === 168) {
    return true;
  }
  return first === 169 && second === 254;
}

function isPrivateIpv6(value: string): boolean {
  const lower: string = value.toLowerCase();
  if (lower === '::1') {
    return true;
  }
  const colon: number = lower.indexOf(':');
  const head: string = colon < 0 ? lower : lower.substring(0, colon);
  if (head.length < 2) {
    return false;
  }
  const pair: string = head.substring(0, 2);
  // Unique local addresses: fc00::/7, so the first byte is 0xfc or 0xfd.
  if (pair === 'fc' || pair === 'fd') {
    return true;
  }
  // Link-local: fe80::/10, so the first group is fe80..febf.
  return head.length === 4 && pair === 'fe' && '89ab'.indexOf(head.charAt(2)) >= 0;
}

/**
 * True when the resolver sits on the local network rather than beyond the relay. Such
 * an address must not be sent into the tunnel: the relay cannot reach it.
 */
export function isLocalDnsAddress(value: string): boolean {
  if (isIpv4(value)) {
    return isPrivateIpv4(value);
  }
  return isIpv6(value) && isPrivateIpv6(value);
}

/**
 * Parses the stored custom resolver list. The addresses are handed straight to
 * VpnConfig, which rejects the whole configuration when one is malformed, so entries
 * are checked again here even though the UI validates on entry.
 */
function parseCustomDns(raw: string): string[] {
  try {
    const parsed: string[] = JSON.parse(raw) as string[];
    if (!Array.isArray(parsed)) {
      return [];
    }
    const valid: string[] = [];
    for (const item of parsed) {
      if (typeof item === 'string' && isValidDnsAddress(item) && valid.indexOf(item) < 0) {
        valid.push(item);
      }
    }
    return valid;
  } catch (e) {
    return [];
  }
}

export class VpnSettings {
  static async load(context: common.Context): Promise<VpnPrefs> {
    try {
      const store = await preferences.getPreferences(context, STORE_NAME);
      const ipVersion: string = await store.get('ipVersion', DEFAULT_PREFS.ipVersion) as string;
      const killSwitch: boolean = await store.get('killSwitch', DEFAULT_PREFS.killSwitch) as boolean;
      const dnsMode: string = await store.get('dnsMode', DEFAULT_PREFS.dnsMode) as string;
      const customDns: string = await store.get('customDns', '[]') as string;
      return {
        // A single-family mode blocks the other family on the carrier, which is what the
        // kill switch does; reporting it off would hide that.
        killSwitch: killSwitch || ipVersion !== 'auto',
        ipVersion: ipVersion,
        multihop: await store.get('multihop', DEFAULT_PREFS.multihop) as boolean,
        dnsBlocking: await store.get('dnsBlocking', DEFAULT_PREFS.dnsBlocking) as boolean,
        directAllowed: await store.get('directAllowed', DEFAULT_PREFS.directAllowed) as boolean,
        daita: await store.get('daita', DEFAULT_PREFS.daita) as boolean,
        dnsMode: normalizeDnsMode(dnsMode),
        customDns: parseCustomDns(customDns),
        blockAds: await store.get('blockAds', DEFAULT_PREFS.blockAds) as boolean,
        blockTrackers: await store.get('blockTrackers', DEFAULT_PREFS.blockTrackers) as boolean,
        blockMalware: await store.get('blockMalware', DEFAULT_PREFS.blockMalware) as boolean,
        blockAdult: await store.get('blockAdult', DEFAULT_PREFS.blockAdult) as boolean,
        blockGambling: await store.get('blockGambling', DEFAULT_PREFS.blockGambling) as boolean,
        blockSocial: await store.get('blockSocial', DEFAULT_PREFS.blockSocial) as boolean
      };
    } catch (e) {
      return DEFAULT_PREFS;
    }
  }

  static async getString(context: common.Context, key: string, fallback: string): Promise<string> {
    try {
      const store = await preferences.getPreferences(context, STORE_NAME);
      return await store.get(key, fallback) as string;
    } catch (e) {
      return fallback;
    }
  }

  static async setString(context: common.Context, key: string, value: string): Promise<void> {
    const store = await preferences.getPreferences(context, STORE_NAME);
    await store.put(key, value);
    await store.flush();
  }

  static async set(context: common.Context, key: string, value: boolean): Promise<void> {
    const store = await preferences.getPreferences(context, STORE_NAME);
    await store.put(key, value);
    await store.flush();
  }
}
