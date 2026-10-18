import { preferences } from '@kit.ArkData';
import { common } from '@kit.AbilityKit';
import { Session } from './MullvadApi';

const STORE_NAME: string = 'muharmony';
const SESSION_KEY: string = 'session';

/**
 * Session persistence.
 *
 * The access token is a bearer credential, so this is deliberately a single JSON blob in
 * the app's preferences store: one place to replace with HUKS-backed storage once the
 * account flow stops changing. It is not a secret store yet, and the file says so.
 */
export class SessionStore {
  private store: preferences.Preferences | null = null;
  private context: common.Context;

  constructor(context: common.Context) {
    this.context = context;
  }

  private async open(): Promise<preferences.Preferences> {
    if (this.store !== null) {
      return this.store;
    }
    this.store = await preferences.getPreferences(this.context, STORE_NAME);
    return this.store;
  }

  async load(): Promise<Session | null> {
    const store = await this.open();
    const raw = await store.get(SESSION_KEY, '') as string;
    if (raw.length === 0) {
      return null;
    }
    try {
      return JSON.parse(raw) as Session;
    } catch (e) {
      return null;
    }
  }

  async save(session: Session): Promise<void> {
    const store = await this.open();
    await store.put(SESSION_KEY, JSON.stringify(session));
    await store.flush();
  }

  async clear(): Promise<void> {
    const store = await this.open();
    await store.delete(SESSION_KEY);
    await store.flush();
  }
}
