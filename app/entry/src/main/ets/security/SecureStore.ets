import { asset } from '@kit.AssetStoreKit';
import { util } from '@kit.ArkTS';

/**
 * Bearer token storage.
 *
 * The access token is a credential, so it goes through Asset Store (HUKS-backed) rather
 * than preferences. Everything else about a session — account number, device id,
 * addresses — is not secret and stays in preferences.
 *
 * Accessibility is DEVICE_FIRST_UNLOCKED: the VPN has to be able to read it after a
 * reboot before the user unlocks, otherwise a reconnect after boot would be impossible.
 */
const ALIAS: string = 'com.maxime.muharmony.session.token';

function encode(text: string): Uint8Array {
  return new util.TextEncoder().encodeInto(text);
}

function decode(bytes: Uint8Array): string {
  return util.TextDecoder.create('utf-8').decodeToString(bytes);
}

function aliasQuery(): asset.AssetMap {
  const query: asset.AssetMap = new Map();
  query.set(asset.Tag.ALIAS, encode(ALIAS));
  return query;
}

export class SecureStore {
  static async save(secret: string): Promise<void> {
    const attributes: asset.AssetMap = new Map();
    attributes.set(asset.Tag.ALIAS, encode(ALIAS));
    attributes.set(asset.Tag.SECRET, encode(secret));
    attributes.set(asset.Tag.ACCESSIBILITY, asset.Accessibility.DEVICE_FIRST_UNLOCKED);
    attributes.set(asset.Tag.CONFLICT_RESOLUTION, asset.ConflictResolution.OVERWRITE);
    await asset.add(attributes);
  }

  static async load(): Promise<string | null> {
    const query = aliasQuery();
    query.set(asset.Tag.RETURN_TYPE, asset.ReturnType.ALL);
    try {
      const rows = await asset.query(query);
      if (rows.length === 0) {
        return null;
      }
      const secret = rows[0].get(asset.Tag.SECRET) as Uint8Array;
      if (secret === undefined) {
        return null;
      }
      return decode(secret);
    } catch (e) {
      // 24000002 (not found) is the normal "no session yet" path.
      return null;
    }
  }

  static async clear(): Promise<void> {
    try {
      await asset.remove(aliasQuery());
    } catch (e) {
      // Removing an absent asset is not an error worth surfacing.
    }
  }
}
