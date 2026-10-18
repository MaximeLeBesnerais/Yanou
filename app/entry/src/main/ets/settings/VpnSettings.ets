import { preferences } from '@kit.ArkData';
import { common } from '@kit.AbilityKit';

/** Tunnel options that belong to the user, not to the account. */
export interface VpnPrefs {
  killSwitch: boolean;
  ipv6: boolean;
  multihop: boolean;
  dnsBlocking: boolean;
  /** Allow the unfronted API path. Off keeps api.mullvad.net out of DNS and SNI. */
  directAllowed: boolean;
  /** Restrict relays and the tunnel to DAITA-capable ones. */
  daita: boolean;
}

export const DEFAULT_PREFS: VpnPrefs = {
  killSwitch: false,
  ipv6: true,
  multihop: false,
  dnsBlocking: false,
  directAllowed: false,
  daita: false
};

const STORE_NAME: string = 'muharmony-settings';

export class VpnSettings {
  static async load(context: common.Context): Promise<VpnPrefs> {
    try {
      const store = await preferences.getPreferences(context, STORE_NAME);
      return {
        killSwitch: await store.get('killSwitch', DEFAULT_PREFS.killSwitch) as boolean,
        ipv6: await store.get('ipv6', DEFAULT_PREFS.ipv6) as boolean,
        multihop: await store.get('multihop', DEFAULT_PREFS.multihop) as boolean,
        dnsBlocking: await store.get('dnsBlocking', DEFAULT_PREFS.dnsBlocking) as boolean,
        directAllowed: await store.get('directAllowed', DEFAULT_PREFS.directAllowed) as boolean,
        daita: await store.get('daita', DEFAULT_PREFS.daita) as boolean
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
