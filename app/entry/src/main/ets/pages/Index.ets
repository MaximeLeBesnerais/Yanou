import { vpnExtension, connection, socket } from '@kit.NetworkKit';
import { commonEventManager, BusinessError, pasteboard, zlib } from '@kit.BasicServicesKit';
import { common, Want, wantAgent, WantAgent } from '@kit.AbilityKit';
import { promptAction } from '@kit.ArkUI';
import { backgroundTaskManager } from '@kit.BackgroundTasksKit';
import { notificationManager } from '@kit.NotificationKit';
import { fileIo as fs, picker } from '@kit.CoreFileKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import native from 'libyanou.so';
import { VpnStatePayload, parseVpnState, VPN_STATE_EVENT } from '../common/VpnEvents';
import {
  Session, WireGuardKey, DeviceResponse, ApiError, login, accountData,
  devicesForToken, deleteDevice, tokenExpiring, fetchRelays, RelayItem, RelaySelection,
  ERR_INVALID_ACCOUNT, ERR_INVALID_TOKEN, ERR_MAX_DEVICES, ERR_PUBKEY_IN_USE
} from '../api/MullvadApi';
import { SessionStore } from '../api/SessionStore';
import { SecureStore } from '../security/SecureStore';
import {
  VpnPrefs, DEFAULT_PREFS, VpnSettings, DnsMode, isValidDnsAddress, normalizeDnsAddress
} from '../settings/VpnSettings';
import { DiagEntry, DiagStatusCounts, parseDiagLog, statusCounts } from '../diagnostics/DiagLog';

const DOMAIN = 0x0002;
const TAG = 'YanouUi';

const VPN_BUNDLE: string = 'com.maxime.muharmony';
const VPN_ABILITY: string = 'YanouVpnAbility';

/** Shown in exports and the About screen; bump it with the HAP version. */
const APP_VERSION: string = '0.1.0';

/** One file inside a diagnostics export. */
interface DiagManifestFile {
  name: string;
  target: string;
  exit: string;
  multihop: boolean;
  startedAt: string;
  status: string;
  lines: number;
}

/** `manifest.json` at the root of a diagnostics zip. */
interface DiagManifest {
  app: string;
  version: string;
  exportedAt: string;
  entryCount: number;
  nodes: string[];
  files: DiagManifestFile[];
}

const CARD_RADIUS: number = 16;
const PAGE_GUTTER: number = 16;
const CONTENT_MAX_WIDTH: number = 720;
const TOKEN_MARGIN_MS: number = 5 * 60 * 1000;
/** Ongoing status notification: relay, state, Disconnect/Reconnect. */
const VPN_NOTIFICATION_ID: number = 1001;
/** One-shot notification when automatic reconnect gives up. */
const FAILURE_NOTIFICATION_ID: number = 1002;
/**
 * Base tun MTU, mirrored from `VpnExtensionAbility`: a single-hop tunnel uses it. A
 * multihop tunnel spends one more WireGuard header per packet and lowers it.
 */
const TUN_MTU: number = 1420;
/** Bytes the second WireGuard header adds: outer IP, UDP and the WireGuard data header. */
const MULTIHOP_IPV4_OVERHEAD: number = 60;
const MULTIHOP_IPV6_OVERHEAD: number = 80;
/** Below this, IPv6 stops working; a multihop tunnel never configures a smaller MTU. */
const MIN_MULTIHOP_MTU: number = 1280;

/**
 * The exit relay of a multihop connection.
 *
 * Kept apart from `RelaySelection` because an exit is always one specific relay: there is
 * no "any relay in this country" exit, and the entry choice stays where it is.
 */
interface ExitChoice {
  hostname: string;
  ipv4: string;
  ipv6: string;
  publicKey: string;
  city: string;
  country: string;
}

function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function formatUptime(milliseconds: number): string {
  const total: number = Math.floor(milliseconds / 1000);
  const minutes: number = Math.floor(total / 60);
  const seconds: number = total % 60;
  return `${minutes}:${seconds < 10 ? '0' : ''}${seconds}`;
}

function formatDate(iso: string): string {
  const at: number = Date.parse(iso);
  if (isNaN(at)) {
    return iso;
  }
  return new Date(at).toISOString().slice(0, 10);
}

function maskAccount(account: string): string {
  const digits: string = account.replace(/ /g, '');
  if (digits.length <= 4) {
    return digits;
  }
  return `•••• •••• •••• ${digits.slice(-4)}`;
}

@Entry
@Component
struct Index {
  private pageStack: NavPathStack = new NavPathStack();

  // Session
  @State session: Session | null = null;
  @State accountNumber: string = '';
  @State loginBusy: boolean = false;
  /** Account used last time, offered as a one-tap sign-in. */
  @State lastAccount: string = '';
  /**
   * Bumped by every sign-out. A sign-in captures it and refuses to persist anything if it
   * changed while the request was in flight — otherwise a slow login can complete after a
   * sign-out and resurrect a session whose key file was already deleted.
   */
  private authGeneration: number = 0;
  @State loginError: string = '';
  @State canManageDevices: boolean = false;
  private pendingToken: string = '';

  // Tunnel
  @State connected: boolean = false;
  @State phase: string = 'idle';
  @State busy: boolean = false;
  @State packets: number = 0;
  @State bytes: number = 0;
  @State rxBytes: number = 0;
  @State txBytes: number = 0;
  @State uptimeMs: number = 0;
  @State protectedFd: number = -1;
  @State errorText: string = '';
  @State extensionKey: string = '';
  @State tunnelTarget: string = '';
  /** Attempt in flight, mirrored from the extension: number, endpoint, family, transport. */
  @State attempt: number = 0;
  @State transport: string = '';
  @State family: string = '';
  @State endpoint: string = '';
  /** Milliseconds from "device up" to the handshake, 0 while unknown. */
  @State handshakeMs: number = 0;
  /** Connection details sheet: a read-only mirror of the payload, no other state. */
  @State detailsVisible: boolean = false;
  /** Relay to push to the back of the candidate list, set by Reconnect. */
  private avoidHostname: string = '';
  @State uiKey: string = '';
  private subscriber: commonEventManager.CommonEventSubscriber | undefined = undefined;
  /** Continuous task: without it HarmonyOS freezes the app and the VPN dies silently. */
  @State keepAlive: boolean = false;
  /** Last time the tunnel process published anything, used to detect a silent drop. */
  private lastStateAt: number = 0;
  private watchdog: number = -1;
  /** The page is foreground; the state broadcasts are suspended in background. */
  private visible: boolean = true;
  private visibleAt: number = 0;
  /** Notification actions from EntryAbility (`disconnect` / `reconnect`). */
  @StorageLink('notificationAction') @Watch('onNotificationAction') notificationAction: string = '';
  private notificationKey: string = '';
  private notificationPermissionAsked: boolean = false;
  private keepAliveFailures: number = 0;
  // Auto-reconnect ladder
  private lastRelayHostname: string = '';
  private forceHostname: string = '';
  private sameRelayRetriesLeft: number = 2;
  private otherRelayTried: boolean = false;
  private retrying: boolean = false;
  private store: SessionStore | null = null;

  // Devices
  @State devices: DeviceResponse[] = [];
  @State devicesBusy: boolean = false;
  @State devicesError: string = '';
  @State removingId: string = '';

  // Account
  @State revealAccount: boolean = false;
  @State accountExpiry: string = '';
  /** Raw account expiry from /accounts/me; `accountExpiry` is its formatted form. */
  @State accountExpiryIso: string = '';
  /** Devices are read-only until "Manage" is tapped, so delete is a deliberate act. */
  @State acctEditDevices: boolean = false;
  @State accountBusy: boolean = false;

  // Servers
  @State relays: RelayItem[] = [];
  @State relaysBusy: boolean = false;
  @State relaysError: string = '';
  /** Bridges are what makes the client usable on a network that drops the relays. */
  @State hasBridges: boolean = false;
  /** A cache written before relays carried `ipv6` has to be refetched. */
  @State cacheNeedsRefresh: boolean = false;
  @State selection: RelaySelection | null = null;
  /** Multihop exit relay; independent of the entry `selection` above. */
  @State exitSelection: ExitChoice | null = null;
  /** What the server browser is editing: the entry relay (`entry`) or the exit (`exit`). */
  @State serverMode: string = 'entry';
  @State logText: string = '';
  @State diagEntries: DiagEntry[] = [];
  @State openEntry: DiagEntry | null = null;
  @State diagnosticsEnabled: boolean = false;
  /** Diagnostics list filter: all | failed | connected | stopped. */
  @State diagFilter: string = 'all';
  /** True while the logs screen is tailing the log file. */
  @State diagLive: boolean = false;
  private diagTailTimer: number = -1;
  @State search: string = '';
  @State expandedCountry: string = '';
  @State recentsJson: string = '[]';
  @State usageJson: string = '{}';
  /** Server browser filter chip: all | daita | owned | recent. */
  @State srvFilter: string = 'all';
  /** Favourites are stored as a JSON array of hostnames under the `favourites` key. */
  @State srvFavouritesJson: string = '[]';

  // Settings
  @State prefs: VpnPrefs = DEFAULT_PREFS;
  @State settingsReady: boolean = false;
  /** Protocol preference (`auto` / `direct` / `obfuscated`); the tunnel reads the same key. */
  @State protocolMode: string = 'auto';
  /** Custom DNS editor: the field being typed and the validation message under it. */
  @State dnsInput: string = '';
  @State dnsError: string = '';

  onPageShow(): void {
    this.visible = true;
    this.visibleAt = Date.now();
  }

  onPageHide(): void {
    this.visible = false;
  }

  aboutToAppear(): void {
    // The native core needs its files directory for the key and the relay cache. Doing
    // this here rather than in signIn() means a restored session can fetch relays too.
    native.init(getContext(this).filesDir);
    this.store = new SessionStore(getContext(this) as common.Context);
    this.loadSettings();
    this.restoreSession();
    this.restoreSelection();
    this.subscribeState();
    this.visibleAt = Date.now();
    this.watchdog = setInterval(() => {
      this.checkLiveness();
    }, 2000);
  }

  aboutToDisappear(): void {
    if (this.watchdog >= 0) {
      clearInterval(this.watchdog);
      this.watchdog = -1;
    }
    this.diagStopTail();
    if (this.subscriber !== undefined) {
      commonEventManager.unsubscribe(this.subscriber);
      this.subscriber = undefined;
    }
  }

  private async restoreSelection(): Promise<void> {
    const raw: string = await VpnSettings.getString(getContext(this) as common.Context,
      'selectedRelay', '');
    if (raw.length > 0) {
      try {
        this.selection = JSON.parse(raw) as RelaySelection;
      } catch (e) {
        hilog.warn(DOMAIN, TAG, 'bad stored relay selection');
      }
    }
    const exitRaw: string = await VpnSettings.getString(getContext(this) as common.Context,
      'exitRelay', '');
    if (exitRaw.length > 0) {
      try {
        this.exitSelection = JSON.parse(exitRaw) as ExitChoice;
      } catch (e) {
        hilog.warn(DOMAIN, TAG, 'bad stored exit relay');
      }
    }
    this.recentsJson = await VpnSettings.getString(getContext(this) as common.Context,
      'recents', '[]');
    this.usageJson = await VpnSettings.getString(getContext(this) as common.Context,
      'usage', '{}');
  }

  private relayCachePath(): string {
    return `${getContext(this).filesDir}/relays.json`;
  }

  private applyRelays(payload: Record<string, RelayItem[]>): void {
    try {
      const items: RelayItem[] = payload['relays'];
      if (items === undefined) {
        return;
      }
      for (const item of items) {
        if (item.ipv6 === undefined || item.ipv6 === null || item.ssExtra === undefined ||
          item.ssExtra === null) {
          this.cacheNeedsRefresh = true;
        }
      }
      this.relays = items.filter((relay: RelayItem) =>
        relay.active && (!this.prefs.daita || relay.daita))
        .sort((a: RelayItem, b: RelayItem) => {
          const left: string = `${a.country}|${a.city}|${a.hostname}`;
          const right: string = `${b.country}|${b.city}|${b.hostname}`;
          return left < right ? -1 : (left > right ? 1 : 0);
        });
    } catch (e) {
      hilog.warn(DOMAIN, TAG, 'relay cache parse failed');
    }
  }

  /** Reads the relay file the native core wrote earlier, so opening the screen is instant. */
  private loadCachedRelays(): void {
    const path: string = this.relayCachePath();
    try {
      if (!fs.accessSync(path)) {
        return;
      }
      const payload = JSON.parse(fs.readTextSync(path)) as Record<string, Object>;
      this.applyRelays(payload as Record<string, RelayItem[]>);
      const bridges = payload['bridges'];
      this.hasBridges = bridges !== undefined && (bridges as Object[]).length > 0;
    } catch (e) {
      hilog.warn(DOMAIN, TAG, 'relay cache read failed');
    }
  }

  private usageMap(): Map<string, number> {
    const map = new Map<string, number>();
    try {
      const parsed = JSON.parse(this.usageJson) as Record<string, number>;
      for (const key of Object.keys(parsed)) {
        map.set(key, parsed[key]);
      }
    } catch (e) {
      // A corrupt usage map is not worth failing over.
    }
    return map;
  }

  private recentHostnames(): string[] {
    try {
      return JSON.parse(this.recentsJson) as string[];
    } catch (e) {
      return [];
    }
  }

  private recentRelays(): RelayItem[] {
    const items: RelayItem[] = [];
    for (const hostname of this.recentHostnames()) {
      for (const relay of this.relays) {
        if (relay.hostname === hostname) {
          items.push(relay);
          break;
        }
      }
    }
    return items;
  }

  private filteredRelays(): RelayItem[] {
    const query: string = this.search.trim().toLowerCase();
    if (query.length === 0) {
      return this.relays;
    }
    return this.relays.filter((relay: RelayItem) =>
      relay.hostname.toLowerCase().includes(query) ||
      relay.city.toLowerCase().includes(query) ||
      relay.country.toLowerCase().includes(query));
  }

  /** Countries ordered by how often you have connected through them. */
  private countries(): string[] {
    const usage = this.usageMap();
    const names: string[] = [];
    for (const relay of this.filteredRelays()) {
      const name: string = relay.country.length > 0 ? relay.country : relay.location;
      if (!names.includes(name)) {
        names.push(name);
      }
    }
    names.sort((a: string, b: string) => {
      const left: number = usage.get(a) ?? 0;
      const right: number = usage.get(b) ?? 0;
      if (left !== right) {
        return right - left;
      }
      return a < b ? -1 : (a > b ? 1 : 0);
    });
    return names;
  }

  private relaysInCountry(country: string): RelayItem[] {
    return this.filteredRelays().filter((relay: RelayItem) =>
      (relay.country.length > 0 ? relay.country : relay.location) === country);
  }

  private usageCount(country: string): number {
    return this.usageMap().get(country) ?? 0;
  }

  /**
   * Opens the relay browser. `mode` is `entry` for the current selection, or `exit` for
   * the multihop exit; the same list, rows and filters are reused for both.
   */
  private async openServers(mode: string = 'entry'): Promise<void> {
    this.serverMode = mode;
    this.loadCachedRelays();
    this.pageStack.pushPath({ name: 'servers' });
    const stamp: string = await VpnSettings.getString(getContext(this) as common.Context,
      'relaysFetchedAt', '0');
    const age: number = Date.now() - Number.parseInt(stamp, 10);
    // The relay list changes daily at most; refetching on every open just hammers the API.
    if (this.relays.length === 0 || isNaN(age) || age > 24 * 60 * 60 * 1000) {
      await this.refreshRelays();
    }
  }

  private async refreshRelays(): Promise<void> {
    if (this.relaysBusy) {
      return;
    }
    this.relaysBusy = true;
    this.relaysError = '';
    try {
      await fetchRelays();
      this.cacheNeedsRefresh = false;
      this.loadCachedRelays();
      await VpnSettings.setString(getContext(this) as common.Context, 'relaysFetchedAt',
        `${Date.now()}`);
    } catch (e) {
      this.relaysError = this.describeError(e as Object);
    } finally {
      this.relaysBusy = false;
    }
  }

  private async loadRelays(): Promise<void> {
    if (this.relaysBusy) {
      return;
    }
    this.relaysBusy = true;
    this.relaysError = '';
    try {
      const items: RelayItem[] = await fetchRelays();
      this.relays = items.filter((relay: RelayItem) =>
        relay.active && (!this.prefs.daita || relay.daita))
        .sort((a: RelayItem, b: RelayItem) => {
          const left: string = `${a.country}|${a.city}|${a.hostname}`;
          const right: string = `${b.country}|${b.city}|${b.hostname}`;
          return left < right ? -1 : (left > right ? 1 : 0);
        });
    } catch (e) {
      this.relaysError = this.describeError(e as Object);
    } finally {
      this.relaysBusy = false;
    }
  }

  private matchingCountries(): string[] {
    const query: string = this.search.trim().toLowerCase();
    if (query.length === 0) {
      return [];
    }
    return this.countries().filter((country: string) => country.toLowerCase().includes(query));
  }

  private async selectCountry(country: string): Promise<void> {
    this.avoidHostname = '';
    const selection: RelaySelection = {
      kind: 'country',
      country: country,
      city: '',
      hostname: '',
      ipv4: '',
      publicKey: ''
    };
    this.bumpUsage(country);
    await this.connectSelection(selection);
  }

  private async selectRelay(relay: RelayItem): Promise<void> {
    this.avoidHostname = '';
    const selection: RelaySelection = {
      kind: 'relay',
      hostname: relay.hostname,
      ipv4: relay.ipv4,
      publicKey: relay.publicKey,
      city: relay.city,
      country: relay.country
    };
    const recents: string[] = this.recentHostnames().filter((item: string) =>
      item !== selection.hostname);
    recents.unshift(selection.hostname);
    this.recentsJson = JSON.stringify(recents.slice(0, 5));
    await VpnSettings.setString(getContext(this) as common.Context, 'recents', this.recentsJson);
    this.bumpUsage(selection.country.length > 0 ? selection.country : selection.city);
    await this.connectSelection(selection);
  }

  private async selectAutomatic(): Promise<void> {
    await this.connectSelection(null);
  }

  /**
   * Saves the exit relay. A live tunnel is rebuilt so the new circuit takes effect now;
   * the entry selection is untouched.
   */
  private async selectExitRelay(relay: RelayItem): Promise<void> {
    await this.applyExitChoice({
      hostname: relay.hostname,
      ipv4: relay.ipv4,
      ipv6: relay.ipv6,
      publicKey: relay.publicKey,
      city: relay.city,
      country: relay.country
    });
  }

  /** Clears the exit: multihop stays enabled but the tunnel falls back to single hop. */
  private async clearExit(): Promise<void> {
    await this.applyExitChoice(null);
  }

  private async applyExitChoice(choice: ExitChoice | null): Promise<void> {
    this.exitSelection = choice;
    await VpnSettings.setString(getContext(this) as common.Context, 'exitRelay',
      choice === null ? '' : JSON.stringify(choice));
    this.pageStack.pop();
    if (this.sessionActive()) {
      await this.reconnectTunnel();
    }
  }

  /** Counts a country use, which also decides the order of the list. */
  private bumpUsage(country: string): void {
    if (country.length === 0) {
      return;
    }
    const usage = this.usageMap();
    usage.set(country, (usage.get(country) ?? 0) + 1);
    const plain: Record<string, number> = {};
    usage.forEach((count: number, key: string) => {
      plain[key] = count;
    });
    this.usageJson = JSON.stringify(plain);
    VpnSettings.setString(getContext(this) as common.Context, 'usage', this.usageJson);
  }

  private relayLabel(): string {
    if (this.selection === null) {
      return 'Automatic';
    }
    if (this.selection.kind === 'country') {
      return `${this.selection.country} · automatic`;
    }
    return this.selection.hostname;
  }

  /** True when the UI asked for multihop and an exit relay is actually selected. */
  private multihopActive(): boolean {
    return this.prefs.multihop && this.exitSelection !== null;
  }

  /** Primary address of the exit, matching the extension's choice (IPv4 first). */
  private exitAddress(): string {
    if (this.exitSelection === null) {
      return '';
    }
    return this.exitSelection.ipv4.length > 0 ? this.exitSelection.ipv4 : this.exitSelection.ipv6;
  }

  /** Human label for the selected exit: city and country when known, else the host. */
  private exitLabel(): string {
    if (this.exitSelection === null) {
      return 'Not selected';
    }
    if (this.exitSelection.city.length > 0) {
      return `${this.exitSelection.city}, ${this.exitSelection.country}`;
    }
    return this.exitSelection.hostname;
  }

  /** MTU the extension will configure: one header less for multihop, floored at 1280. */
  /**
   * Resolver the tunnel will use, mirroring what the extension puts in
   * `VpnConfig.dnsAddresses`: the custom list when one is set, otherwise a blocking
   * resolver encoded as `100.64.0.<mask>` or the default `10.64.0.1`.
   */
  private dnsLabel(): string {
    if (this.prefs.dnsMode === 'custom' && this.prefs.customDns.length > 0) {
      return this.prefs.customDns.join(', ');
    }
    let mask: number = 0;
    if (this.prefs.blockAds) {
      mask |= 1;
    }
    if (this.prefs.blockTrackers) {
      mask |= 2;
    }
    if (this.prefs.blockMalware) {
      mask |= 4;
    }
    if (this.prefs.blockAdult) {
      mask |= 8;
    }
    if (this.prefs.blockGambling) {
      mask |= 16;
    }
    if (this.prefs.blockSocial) {
      mask |= 32;
    }
    return mask === 0 ? '10.64.0.1' : `100.64.0.${mask}`;
  }

  /** One-line state for the DNS row on the settings screen. */
  private dnsSummary(): string {
    if (this.prefs.dnsMode === 'custom' && this.prefs.customDns.length > 0) {
      const count: number = this.prefs.customDns.length;
      return `Custom · ${count} resolver${count > 1 ? 's' : ''}`;
    }
    const labels: string[] = [];
    if (this.prefs.blockAds) {
      labels.push('ads');
    }
    if (this.prefs.blockTrackers) {
      labels.push('trackers');
    }
    if (this.prefs.blockMalware) {
      labels.push('malware');
    }
    if (this.prefs.blockAdult) {
      labels.push('adult content');
    }
    if (this.prefs.blockGambling) {
      labels.push('gambling');
    }
    if (this.prefs.blockSocial) {
      labels.push('social media');
    }
    return labels.length === 0 ? 'Automatic · no blocking' : `Automatic · blocking ${labels.join(', ')}`;
  }

  private effectiveMtu(): number {
    if (!this.multihopActive()) {
      return TUN_MTU;
    }
    const overhead: number = this.exitAddress().includes(':') ?
      MULTIHOP_IPV6_OVERHEAD : MULTIHOP_IPV4_OVERHEAD;
    return Math.max(MIN_MULTIHOP_MTU, TUN_MTU - overhead);
  }

  /** One line for the tunnel configuration card, never claims a circuit that is not set. */
  private multihopSummary(): string {
    if (!this.prefs.multihop) {
      return 'Multihop off';
    }
    if (this.exitSelection === null) {
      return 'Multihop on · no exit selected (single hop)';
    }
    return `Multihop · exit ${this.exitLabel()}`;
  }

  private readLogs(): void {
    const path: string = `${getContext(this).filesDir}/yanou-native.log`;
    try {
      if (!fs.accessSync(path)) {
        this.logText = '';
        this.diagEntries = [];
        return;
      }
      this.logText = fs.readTextSync(path);
      this.diagEntries = parseDiagLog(this.logText);
    } catch (e) {
      this.logText = `Log read failed: ${JSON.stringify(e)}`;
      this.diagEntries = [];
    }
  }

  /** One entry per connect attempt; `entry` opens as its own destination. */
  private openDiagnostics(entry: DiagEntry): void {
    this.openEntry = entry;
    this.pageStack.pushPath({ name: 'entry' });
  }


  private async loadSettings(): Promise<void> {
    this.prefs = await VpnSettings.load(getContext(this) as common.Context);
    native.setDirectAllowed(this.prefs.directAllowed);
    const diagnostics: string = await VpnSettings.getString(getContext(this) as common.Context,
      'diagnostics', 'false');
    this.diagnosticsEnabled = diagnostics === 'true';
    native.setDiagnostics(this.diagnosticsEnabled);
    this.settingsReady = true;
    this.loadCachedRelays();
    VpnSettings.getString(getContext(this) as common.Context, 'lastAccount', '').then(
      (stored: string) => {
        // Do not clobber the value restored from the existing session.
        if (stored.length > 0) {
          this.lastAccount = stored;
        }
      });
    if (!this.hasBridges || this.cacheNeedsRefresh) {
      // An older cache has relays but no bridge list; refetch once so the tunnel has a
      // way out on networks that drop the relay IPs.
      this.refreshRelays();
    }
  }

  // ------------------------------------------------------------- notifications

  private async actionAgent(action: string, code: number): Promise<WantAgent | undefined> {
    try {
      const info: wantAgent.WantAgentInfo = {
        wants: [{
          bundleName: 'com.maxime.muharmony',
          abilityName: 'EntryAbility',
          parameters: { 'notificationAction': action }
        }],
        actionType: wantAgent.OperationType.START_ABILITY,
        requestCode: code,
        actionFlags: [wantAgent.WantAgentFlags.UPDATE_PRESENT_FLAG]
      };
      return await wantAgent.getWantAgent(info);
    } catch (e) {
      hilog.warn(DOMAIN, TAG, 'wantAgent failed for %{public}s', action);
      return undefined;
    }
  }

  private async ensureNotificationPermission(): Promise<boolean> {
    try {
      if (await notificationManager.isNotificationEnabled()) {
        return true;
      }
      if (!this.notificationPermissionAsked) {
        this.notificationPermissionAsked = true;
        await notificationManager.requestEnableNotification(getContext(this) as common.UIAbilityContext);
      }
      return await notificationManager.isNotificationEnabled();
    } catch (e) {
      const err = e as BusinessError;
      hilog.warn(DOMAIN, TAG, 'notification permission %{public}d', err.code ?? -1);
      return false;
    }
  }

  /** Keeps one notification in sync with the tunnel: relay name plus actions. */
  private async refreshNotification(): Promise<void> {
    const key: string = `${this.phase}|${this.tunnelTarget}`;
    if (key === this.notificationKey) {
      return;
    }
    this.notificationKey = key;

    if (this.phase === 'idle') {
      try {
        await notificationManager.cancel(VPN_NOTIFICATION_ID);
      } catch (e) {
        // Nothing published yet.
      }
      return;
    }
    if (!(await this.ensureNotificationPermission())) {
      return;
    }

    const open: WantAgent | undefined = await this.actionAgent('', 0);
    const reconnect: WantAgent | undefined = await this.actionAgent('reconnect', 1);
    const disconnect: WantAgent | undefined = await this.actionAgent('disconnect', 2);
    const buttons: notificationManager.NotificationActionButton[] = [];
    if (this.phase === 'connecting' || this.phase === 'connected') {
      if (disconnect !== undefined) {
        buttons.push({ title: 'Disconnect', wantAgent: disconnect });
      }
      if (reconnect !== undefined) {
        buttons.push({ title: 'Reconnect', wantAgent: reconnect });
      }
    } else if (reconnect !== undefined) {
      buttons.push({ title: 'Reconnect', wantAgent: reconnect });
    }

    let title: string = 'Yanou';
    let text: string = '';
    if (this.phase === 'connected') {
      title = '燕鸥 · Connected';
      text = this.tunnelTarget.length > 0 ? this.tunnelTarget : this.relayLabel();
    } else if (this.phase === 'connecting') {
      title = '燕鸥 · Connecting';
      text = this.tunnelTarget.length > 0 ? this.tunnelTarget : this.relayLabel();
    } else if (this.phase === 'lost') {
      title = '燕鸥 · Connection lost';
      text = this.retrying ? 'Trying to reconnect…' : 'Reconnect to protect traffic again';
    } else if (this.phase === 'failed') {
      title = '燕鸥 · Connection failed';
      text = this.errorText.length > 0 ? this.errorText : 'The tunnel did not come up';
    }

    const request: notificationManager.NotificationRequest = {
      id: VPN_NOTIFICATION_ID,
      content: {
        notificationContentType: notificationManager.ContentType.NOTIFICATION_CONTENT_BASIC_TEXT,
        normal: { title: title, text: text }
      },
      wantAgent: open,
      actionButtons: buttons,
      tapDismissed: false
    };
    try {
      await notificationManager.publish(request);
    } catch (e) {
      const err = e as BusinessError;
      hilog.warn(DOMAIN, TAG, 'publish notification %{public}d', err.code ?? -1);
    }
  }

  /** One-shot notification: automatic reconnect gave up. */
  private async publishFailureNotification(): Promise<void> {
    if (!(await this.ensureNotificationPermission())) {
      return;
    }
    const open: WantAgent | undefined = await this.actionAgent('', 3);
    const reconnect: WantAgent | undefined = await this.actionAgent('reconnect', 4);
    const buttons: notificationManager.NotificationActionButton[] = [];
    if (reconnect !== undefined) {
      buttons.push({ title: 'Reconnect', wantAgent: reconnect });
    }
    try {
      await notificationManager.cancel(VPN_NOTIFICATION_ID);
    } catch (e) {
      // Nothing to cancel.
    }
    const request: notificationManager.NotificationRequest = {
      id: FAILURE_NOTIFICATION_ID,
      content: {
        notificationContentType: notificationManager.ContentType.NOTIFICATION_CONTENT_BASIC_TEXT,
        normal: {
          title: '燕鸥 could not reconnect',
          text: 'No relay answered. Open the app to try again.'
        }
      },
      wantAgent: open,
      actionButtons: buttons,
      tapDismissed: true
    };
    try {
      await notificationManager.publish(request);
    } catch (e) {
      const err = e as BusinessError;
      hilog.warn(DOMAIN, TAG, 'publish failure notification %{public}d', err.code ?? -1);
    }
  }

  private onNotificationAction(): void {
    const raw: string = this.notificationAction;
    const separator: number = raw.indexOf(':');
    const action: string = separator > 0 ? raw.substring(0, separator) : raw;
    if (action === 'disconnect') {
      this.stopTunnel();
    } else if (action === 'reconnect') {
      this.reconnectTunnel();
    }
  }

  // ------------------------------------------------------------ auto reconnect

  /**
   * The tunnel died while the user wanted it up: retry the same relay twice, then one
   * different relay, and only then tell the user.
   */
  private handleDrop(reason: string): void {
    if (this.tunnelTarget.length > 0) {
      this.lastRelayHostname = this.tunnelTarget;
    }
    this.phase = 'lost';
    this.connected = false;
    this.tunnelTarget = '';
    this.errorText = reason;
    this.retrying = true;
    this.refreshNotification();
    this.attemptAutoReconnect();
  }

  private attemptAutoReconnect(): void {
    if (this.sameRelayRetriesLeft > 0 && this.lastRelayHostname.length > 0) {
      this.sameRelayRetriesLeft -= 1;
      this.forceHostname = this.lastRelayHostname;
      this.startTunnel();
      return;
    }
    if (!this.otherRelayTried) {
      this.otherRelayTried = true;
      this.forceHostname = '';
      this.avoidHostname = this.lastRelayHostname;
      this.startTunnel();
      return;
    }
    this.retrying = false;
    this.phase = 'failed';
    this.stopKeepAlive();
    this.errorText = 'Every relay failed after the connection was lost.';
    this.refreshNotification();
    this.publishFailureNotification();
  }

  /**
   * Requests a continuous task. The system then keeps the process (and therefore the VPN
   * extension) alive in the background and shows the ongoing-task notification.
   */
  private async startKeepAlive(): Promise<void> {
    if (this.keepAlive || this.keepAliveFailures >= 3) {
      return;
    }
    try {
      const context = getContext(this) as common.UIAbilityContext;
      const info: wantAgent.WantAgentInfo = {
        wants: [{ bundleName: 'com.maxime.muharmony', abilityName: 'EntryAbility' }],
        actionType: wantAgent.OperationType.START_ABILITY,
        requestCode: 0,
        actionFlags: [wantAgent.WantAgentFlags.UPDATE_PRESENT_FLAG]
      };
      const agent = await wantAgent.getWantAgent(info);
      await backgroundTaskManager.startBackgroundRunning(context,
        backgroundTaskManager.BackgroundMode.DATA_TRANSFER, agent);
      this.keepAlive = true;
      this.keepAliveFailures = 0;
      hilog.info(DOMAIN, TAG, 'continuous task started');
    } catch (e) {
      const err = e as BusinessError;
      this.keepAliveFailures += 1;
      hilog.error(DOMAIN, TAG, 'continuous task failed %{public}d', err.code ?? -1);
    }
  }

  private async stopKeepAlive(): Promise<void> {
    if (!this.keepAlive) {
      return;
    }
    try {
      const context = getContext(this) as common.UIAbilityContext;
      await backgroundTaskManager.stopBackgroundRunning(context);
      this.keepAlive = false;
    } catch (e) {
      const err = e as BusinessError;
      hilog.warn(DOMAIN, TAG, 'stop continuous task failed %{public}d', err.code ?? -1);
    }
  }

  /**
   * The tunnel process publishes once per second. Silence while "connected" means the
   * process was killed and the system dropped the VPN — say so instead of lying.
   */
  private checkLiveness(): void {
    if (this.phase !== 'connected' && this.phase !== 'connecting') {
      return;
    }
    // Backgrounded pages do not receive broadcasts; never read that silence as a
    // dead tunnel. After resume, give the next publish five seconds to arrive.
    if (!this.visible || Date.now() - this.visibleAt < 5000) {
      return;
    }
    if (this.lastStateAt === 0 || Date.now() - this.lastStateAt < 5000) {
      return;
    }
    hilog.warn(DOMAIN, TAG, 'tunnel process went silent');
    this.handleDrop('The VPN was dropped: the tunnel process stopped reporting.');
  }

  private subscribeState(): void {
    const info: commonEventManager.CommonEventSubscribeInfo = { events: [VPN_STATE_EVENT] };
    commonEventManager.createSubscriber(info).then((subscriber: commonEventManager.CommonEventSubscriber) => {
      this.subscriber = subscriber;
      commonEventManager.subscribe(subscriber,
        (err: BusinessError, data: commonEventManager.CommonEventData) => {
          if (err) {
            hilog.error(DOMAIN, TAG, 'subscribe error %{public}d', err.code);
            return;
          }
          const state: VpnStatePayload | null = parseVpnState(data.data ?? '');
          if (state === null) {
            return;
          }
          const previousPhase: string = this.phase;
          this.phase = state.phase !== undefined && state.phase.length > 0 ? state.phase : 'idle';
          this.connected = state.connected;
          this.packets = state.packets;
          this.bytes = state.bytes;
          this.rxBytes = state.rxBytes ?? 0;
          this.txBytes = state.txBytes ?? 0;
          this.uptimeMs = state.uptimeMs;
          this.protectedFd = state.protectedFd;
          this.errorText = state.error;
          this.extensionKey = state.publicKey;
          this.tunnelTarget = state.target;
          this.attempt = state.attempt ?? 0;
          this.transport = state.transport ?? '';
          this.family = state.family ?? '';
          this.endpoint = state.endpoint ?? '';
          this.handshakeMs = state.handshakeMs ?? 0;
          this.lastStateAt = Date.now();
          if (this.phase === 'connected') {
            this.lastRelayHostname = this.tunnelTarget;
            // A working tunnel resets the ladder for the next drop.
            this.sameRelayRetriesLeft = 2;
            this.otherRelayTried = false;
            this.retrying = false;
            this.forceHostname = '';
          }
          if (this.phase === 'connected' || this.phase === 'connecting' ||
            this.phase === 'lost') {
            // "lost" means the extension is rebuilding the tunnel itself: the continuous
            // task must survive that, or the rebuild happens without the keep-alive.
            this.startKeepAlive();
          } else if (this.phase === 'idle' || this.phase === 'failed') {
            this.stopKeepAlive();
          }
          if (this.phase === 'lost' && previousPhase !== 'lost') {
            this.retrying = true;
          }
          if (this.phase === 'failed' && previousPhase !== 'failed' && this.retrying) {
            this.attemptAutoReconnect();
          }
          this.refreshNotification();
        });
    }).catch((err: BusinessError) => {
      hilog.error(DOMAIN, TAG, 'createSubscriber failed %{public}d', err.code);
    });
  }

  private async restoreSession(): Promise<void> {
    try {
      const stored: Session | null = await this.store?.load() ?? null;
      if (stored === null) {
        // No account: nothing may be holding the system VPN slot.
        await this.releaseTunnel();
        return;
      }
      const token: string | null = await SecureStore.load();
      if (token === null) {
        // Metadata without a token is not a usable session.
        await this.store?.clear();
        await this.releaseTunnel();
        return;
      }
      stored.token = token;
      this.session = stored;
      this.accountNumber = stored.account;
      if (this.lastAccount.length === 0) {
        // Seed the one-tap login from the session that already exists.
        this.lastAccount = stored.account;
        VpnSettings.setString(getContext(this) as common.Context, 'lastAccount', stored.account);
      }
      this.loadAccountExpiry();
    } catch (e) {
      hilog.error(DOMAIN, TAG, 'restore failed: %{public}s', JSON.stringify(e));
    }
  }

  private async persistSession(session: Session): Promise<void> {
    await SecureStore.save(session.token);
    // A fresh object: clearing the token on the live session would break every later call.
    const metadata: Session = {
      account: session.account,
      token: '',
      expiry: session.expiry,
      deviceId: session.deviceId,
      deviceName: session.deviceName,
      ipv4: session.ipv4,
      ipv6: session.ipv6,
      publicKey: session.publicKey
    };
    await this.store?.save(metadata);
  }

  private describeError(error: Object): string {
    if (error instanceof ApiError) {
      if (error.code === ERR_INVALID_ACCOUNT) {
        return 'That account number is not valid.';
      }
      if (error.code === ERR_MAX_DEVICES) {
        return 'All device slots on this account are in use.';
      }
      if (error.code === ERR_PUBKEY_IN_USE) {
        return 'This device key is already registered to another account.';
      }
      if (error.code === ERR_INVALID_TOKEN) {
        return 'The session expired. Sign in again.';
      }
      return error.message;
    }
    return (error as BusinessError).message ?? 'Something went wrong';
  }

  private async signIn(): Promise<void> {
    if (this.loginBusy) {
      return;
    }
    const generation: number = this.authGeneration;
    this.loginBusy = true;
    this.loginError = '';
    this.canManageDevices = false;
    try {
      native.init(getContext(this).filesDir);
      // Mullvad rejects a device key that was used before, so every sign-in rotates it.
      const key = JSON.parse(native.rotateKey()) as WireGuardKey;
      this.uiKey = key.publicKey;
      const account: string = this.accountNumber.replace(/ /g, '').trim();
      const session: Session = await login(account, key.publicKey);
      if (generation !== this.authGeneration) {
        // Signed out while the request was in flight: drop the device we just created.
        hilog.warn(DOMAIN, TAG, 'sign-in superseded by sign-out; cleaning up');
        try {
          await deleteDevice(session.token, session.deviceId);
        } catch (e) {
          hilog.warn(DOMAIN, TAG, 'cleanup delete failed');
        }
        native.clearKey();
        return;
      }
      const stored: WireGuardKey = JSON.parse(native.deviceKey()) as WireGuardKey;
      if (stored.publicKey !== key.publicKey) {
        // The key never reached disk: remove the device we just registered so the account
        // does not keep an orphan, and tell the user instead of pretending it worked.
        hilog.error(DOMAIN, TAG, 'device key not stored after sign-in');
        try {
          await deleteDevice(session.token, session.deviceId);
        } catch (e) {
          hilog.warn(DOMAIN, TAG, 'cleanup after missing key failed');
        }
        native.clearKey();
        this.loginError = 'The device key could not be stored. Try again.';
        return;
      }
      this.lastAccount = account;
      VpnSettings.setString(getContext(this) as common.Context, 'lastAccount', account);
      this.pendingToken = '';
      this.session = session;
      await this.persistSession(session);
      this.loadAccountExpiry();
      hilog.info(DOMAIN, TAG, 'signed in %{public}s', session.deviceName);
    } catch (e) {
      this.loginError = this.describeError(e as Object);
      if (e instanceof ApiError && e.code === ERR_MAX_DEVICES) {
        this.canManageDevices = true;
        // No session exists yet; the device screen still needs a token to list devices.
        this.pendingToken = e.token;
      }
      hilog.error(DOMAIN, TAG, 'login failed: %{public}s', this.loginError);
    } finally {
      this.loginBusy = false;
    }
  }

  /** Re-requests a token when the stored one is close to expiry. */
  private async freshToken(): Promise<string> {
    const current: Session | null = this.session;
    if (current === null) {
      throw new Error('not signed in');
    }
    if (!tokenExpiring(current.expiry, TOKEN_MARGIN_MS)) {
      return current.token;
    }
    hilog.info(DOMAIN, TAG, 'token expiring, refreshing');
    const refreshed: Session = await login(current.account, current.publicKey);
    current.token = refreshed.token;
    current.expiry = refreshed.expiry;
    this.session = current;
    await this.persistSession(current);
    return refreshed.token;
  }

  private async loadAccountExpiry(): Promise<void> {
    try {
      const token: string = await this.freshToken();
      const data = await accountData(token);
      this.accountExpiryIso = data.expiry;
      this.accountExpiry = formatDate(data.expiry);
    } catch (e) {
      hilog.warn(DOMAIN, TAG, 'account data failed: %{public}s', JSON.stringify(e));
    }
  }

  private async signOut(): Promise<void> {
    // Invalidate any sign-in that is still in flight before we touch the key.
    this.authGeneration += 1;
    const current: Session | null = this.session;
    // Release the system VPN and the notification *before* dropping the session: the
    // extension lives in another process and the slot stays taken until it is torn down.
    await this.releaseTunnel();
    this.session = null;
    this.accountNumber = '';
    this.loginError = '';
    this.accountExpiry = '';
    this.packets = 0;
    this.bytes = 0;
    try {
      if (current !== null) {
        await deleteDevice(current.token, current.deviceId);
      }
    } catch (e) {
      hilog.warn(DOMAIN, TAG, 'device removal failed: %{public}s', JSON.stringify(e));
    }
    native.clearKey();
    this.uiKey = '';
    await SecureStore.clear();
    await this.store?.clear();
    if (this.pageStack.size() > 0) {
      this.pageStack.clear();
    }
  }

  /** Stops the tunnel, the continuous task and the status notification, unconditionally. */
  private async releaseTunnel(): Promise<void> {
    try {
      await vpnExtension.stopVpnExtensionAbility(this.vpnWant());
    } catch (e) {
      hilog.warn(DOMAIN, TAG, 'stop on sign-out rejected');
    }
    try {
      await notificationManager.cancel(VPN_NOTIFICATION_ID);
      await notificationManager.cancel(FAILURE_NOTIFICATION_ID);
    } catch (e) {
      hilog.warn(DOMAIN, TAG, 'notification cancel failed');
    }
    await this.stopKeepAlive();
    this.notificationKey = '';
    this.phase = 'idle';
    this.connected = false;
    this.tunnelTarget = '';
    this.uptimeMs = 0;
    this.retrying = false;
  }

  private async loadDevices(): Promise<void> {
    this.devicesBusy = true;
    this.devicesError = '';
    try {
      let token: string = this.pendingToken;
      if (token.length === 0) {
        token = await this.freshToken();
      }
      this.devices = await devicesForToken(token);
    } catch (e) {
      this.devicesError = this.describeError(e as Object);
    } finally {
      this.devicesBusy = false;
    }
  }

  private confirmRemove(device: DeviceResponse): void {
    AlertDialog.show({
      title: 'Remove device?',
      message: `${device.name} will be signed out and its slot freed.`,
      autoCancel: true,
      primaryButton: {
        value: 'Cancel',
        action: () => {
        }
      },
      secondaryButton: {
        value: 'Remove',
        fontColor: $r('sys.color.alert'),
        action: () => {
          this.removeDevice(device);
        }
      }
    });
  }

  private async removeDevice(device: DeviceResponse): Promise<void> {
    if (this.removingId.length > 0) {
      return;
    }
    this.removingId = device.id;
    this.devicesError = '';
    try {
      let token: string = this.pendingToken;
      if (token.length === 0) {
        token = await this.freshToken();
      }
      await deleteDevice(token, device.id);
      this.devices = this.devices.filter((item: DeviceResponse) => item.id !== device.id);
    } catch (e) {
      this.devicesError = this.describeError(e as Object);
    } finally {
      this.removingId = '';
    }
  }

  private async setPref(key: string, value: boolean): Promise<void> {
    try {
      await VpnSettings.set(getContext(this) as common.Context, key, value);
    } catch (e) {
      hilog.warn(DOMAIN, TAG, 'setting %{public}s failed', key);
    }
  }

  private async setPrefText(key: string, value: string): Promise<void> {
    try {
      await VpnSettings.setString(getContext(this) as common.Context, key, value);
    } catch (e) {
      hilog.warn(DOMAIN, TAG, 'setting %{public}s failed', key);
    }
  }

  @Builder
  ipOption(label: string, value: string) {
    Button(label)
      .fontSize(13)
      .height(34)
      .padding({ left: 14, right: 14 })
      .backgroundColor(this.prefs.ipVersion === value ?
        $r('sys.color.brand') : Color.Transparent)
      .border({
        width: 1,
        color: this.prefs.ipVersion === value ? $r('sys.color.brand') : $r('sys.color.comp_divider')
      })
      .fontColor(this.prefs.ipVersion === value ? Color.White : $r('sys.color.font_primary'))
      .onClick(() => {
        this.prefs.ipVersion = value;
        this.setPrefText('ipVersion', value);
        // Excluding a family turns blocking on: without it the system routes that family
        // around the tunnel and the connections are reset on the carrier. Keep the switch
        // honest rather than blocking behind its back.
        if (value !== 'auto' && !this.prefs.killSwitch) {
          this.prefs.killSwitch = true;
          this.setPref('killSwitch', true);
        }
      })
  }

  /** Ordered relays to try for the current selection. */
  private candidatesForSelection(): RelayItem[] {
    if (this.selection === null) {
      return this.autoCandidates();
    }
    if (this.selection.kind === 'relay') {
      return this.relays.filter((relay: RelayItem) => relay.hostname === this.selection?.hostname);
    }
    return this.relaysInCountry(this.selection.country).slice(0, 8);
  }

  /**
   * "Automatic" without a latency probe: the countries you actually use first, then a
   * random sample of the rest, one relay per country. The engine walks the list, so a
   * dead or filtered relay costs one 5 s attempt instead of the whole connection.
   */
  private autoCandidates(): RelayItem[] {
    if (this.relays.length === 0) {
      return [];
    }
    const usage = this.usageMap();
    const preferred: string[] = [];
    usage.forEach((count: number, key: string) => {
      if (count > 0) {
        preferred.push(key);
      }
    });
    preferred.sort((a: string, b: string) => (usage.get(b) ?? 0) - (usage.get(a) ?? 0));

    const picked: RelayItem[] = [];
    const usedCountries: string[] = [];
    for (const country of preferred) {
      if (picked.length >= 8) {
        break;
      }
      for (const relay of this.relaysInCountry(country)) {
        if (picked.length >= 8) {
          break;
        }
        if (!usedCountries.includes(country)) {
          usedCountries.push(country);
          picked.push(relay);
        }
      }
    }

    // Reconnect: never hand back the relay we were just on, if there is an alternative.
    if (this.avoidHostname.length > 0) {
      const avoided: RelayItem[] = picked.filter((relay: RelayItem) =>
        relay.hostname === this.avoidHostname);
      if (avoided.length > 0 && this.relays.length > avoided.length) {
        for (let index: number = picked.length - 1; index >= 0; index -= 1) {
          if (picked[index].hostname === this.avoidHostname) {
            picked.splice(index, 1);
          }
        }
        picked.push(avoided[0]);
      }
    }

    const rest: RelayItem[] = this.relays.filter((relay: RelayItem) =>
      !usedCountries.includes(relay.country));
    while (rest.length > 0 && picked.length < 8) {
      const index: number = Math.floor(Math.random() * rest.length);
      const relay: RelayItem = rest[index];
      rest.splice(index, 1);
      if (usedCountries.includes(relay.country)) {
        continue;
      }
      usedCountries.push(relay.country);
      picked.push(relay);
    }
    return picked;
  }

  private relayCandidatesJson(): string {
    if (this.forceHostname.length > 0) {
      const forced: RelayItem[] = this.relays.filter((relay: RelayItem) =>
        relay.hostname === this.forceHostname);
      if (forced.length > 0) {
        return JSON.stringify(this.candidatesOf(forced));
      }
    }
    const list: RelayItem[] = this.candidatesForSelection();
    return JSON.stringify(this.candidatesOf(list));
  }

  private candidatesOf(list: RelayItem[]): Record<string, Object>[] {
    const candidates: Record<string, Object>[] = [];
    for (const relay of list) {
      const entry: Record<string, Object> = {
        'hostname': relay.hostname,
        'ip': relay.ipv4,
        'ipv6': relay.ipv6,
        'publicKey': relay.publicKey,
        'ssExtra': relay.ssExtra !== undefined && relay.ssExtra !== null ? relay.ssExtra : []
      };
      // Optional capabilities travel with the relay so the extension can pick a
      // transport. A relay list cached by an older build has neither field.
      if (relay.lwo !== undefined && relay.lwo !== null) {
        entry['lwo'] = relay.lwo;
      }
      if (relay.lwoV2 !== undefined && relay.lwoV2 !== null) {
        entry['lwoV2'] = relay.lwoV2;
      }
      if (relay.quic !== undefined && relay.quic !== null) {
        entry['quic'] = relay.quic;
      }
      candidates.push(entry);
    }
    return candidates;
  }

  private vpnWant(): Want {
    // The IPv6 address is always claimed, whatever the mode: it is what installs the ::/0
    // route, and the family that is not forwarded still has to be routed into the tunnel
    // so the engine can drop it instead of letting it escape unprotected.
    const ipv6: string = this.session === null ? '' : this.session.ipv6;
    const parameters: Record<string, Object> = {
      'ipv6': ipv6,
      'ipVersion': this.prefs.ipVersion,
      'killSwitch': this.prefs.killSwitch,
      'target': this.relayLabel(),
      'relayIp': this.selection !== null && this.selection.kind === 'relay' ?
        this.selection.ipv4 : '',
      'relayKey': this.selection !== null && this.selection.kind === 'relay' ?
        this.selection.publicKey : '',
      'relayCandidates': this.relayCandidatesJson(),
      // The address the account assigned to this device; 10.64.0.1 is only the gateway.
      'tunnelIpv4': this.session !== null ? this.session.ipv4 : '',
      // The extension refuses to run with any other key than this one.
      'expectKey': this.session !== null ? this.session.publicKey : '',
      // The extension is a separate process with its own native instance; it has to be
      // told about diagnostics itself, before it writes the connection marker.
      'diagnostics': this.diagnosticsEnabled
    };
    // Multihop exit. Only sent while the toggle is on and a relay is chosen: the extension
    // treats the absence of these fields as a single-hop connection, which is what a
    // half-configured multihop must behave like.
    const exit: ExitChoice | null = this.exitSelection;
    if (this.prefs.multihop && exit !== null) {
      parameters['exitHostname'] = exit.hostname;
      parameters['exitIpv4'] = exit.ipv4;
      parameters['exitIpv6'] = exit.ipv6;
      parameters['exitKey'] = exit.publicKey;
    }
    return {
      bundleName: VPN_BUNDLE,
      abilityName: VPN_ABILITY,
      parameters: parameters
    };
  }

  private async toggleTunnel(): Promise<void> {
    if (this.sessionActive()) {
      await this.stopTunnel();
    } else {
      await this.startTunnel();
    }
  }

  /** Drops the tunnel and starts a new one on a different relay. */
  private async reconnectTunnel(): Promise<void> {
    if (this.busy) {
      return;
    }
    // Remember what we were on so "Automatic" does not hand back the same relay.
    this.avoidHostname = this.tunnelTarget;
    await this.stopTunnel();
    await this.startTunnel();
  }

  private async stopTunnel(): Promise<void> {
    if (this.busy) {
      return;
    }
    this.busy = true;
    this.errorText = '';
    try {
      await vpnExtension.stopVpnExtensionAbility(this.vpnWant());
    } catch (e) {
      hilog.warn(DOMAIN, TAG, 'stop rejected');
    } finally {
      this.connected = false;
      this.packets = 0;
      this.bytes = 0;
      this.rxBytes = 0;
      this.txBytes = 0;
      this.uptimeMs = 0;
      this.tunnelTarget = '';
      this.retrying = false;
      this.phase = 'idle';
      this.busy = false;
      this.refreshNotification();
    }
  }

  private async startTunnel(): Promise<void> {
    // Cold start: the extension publishes its state once a second, so the UI can still be
    // looking at an empty field when this runs. Wait for one publication before deciding.
    if (this.lastStateAt === 0) {
      await new Promise<void>((resolve: () => void) => {
        setTimeout(() => {
          resolve();
        }, 1300);
      });
    }
    // The tunnel runs in its own process and survives the UI process. Reopening the app must
    // not tear a healthy tunnel down and dial again, which is what the reconnect-on-open was.
    if (this.phase === 'connected' || this.phase === 'connecting') {
      hilog.info(0x0000, 'Yanou', 'startTunnel skipped: already %{public}s', this.phase);
      return;
    }
    if (this.busy) {
      return;
    }
    this.busy = true;
    this.errorText = '';
    try {
      // A failed or running attempt leaves an ability behind; clear it first so the
      // system does not reject the new start with "VPN exist already".
      if (this.phase !== 'idle') {
        try {
          await vpnExtension.stopVpnExtensionAbility(this.vpnWant());
        } catch (e) {
          hilog.warn(DOMAIN, TAG, 'cleanup stop failed');
        }
        this.phase = 'idle';
        this.connected = false;
        await new Promise<void>((resolve: (value: void) => void) => {
          setTimeout(() => {
            resolve();
          }, 250);
        });
      }
      this.retrying = false;
      this.sameRelayRetriesLeft = 2;
      this.otherRelayTried = false;
      this.keepAliveFailures = 0;
      const candidates: RelayItem[] = this.candidatesForSelection();
      const circuit: string = this.multihopActive() ? ` · exit ${this.exitLabel()}` : '';
      native.logLine(`connect: ${this.relayLabel()}${circuit} · ${candidates.length} candidate(s)` +
        (candidates.length > 0 ? ` · first ${candidates[0].hostname} (${candidates[0].ipv4})` : ''));
      await vpnExtension.startVpnExtensionAbility(this.vpnWant());
      this.phase = 'connecting';
      if (this.diagnosticsEnabled && this.session !== null) {
        this.checkRegistration(this.session.token, this.session.publicKey);
      }
    } catch (e) {
      const err = e as BusinessError;
      this.errorText = `${err.code ?? -1}: ${err.message ?? 'request rejected'}`;
      this.phase = 'failed';
    } finally {
      this.busy = false;
    }
  }

  /**
   * A relay drops a handshake from a key it does not know, without any error. Recording
   * whether this key is still on the account turns a silent 30 s timeout into an answer.
   */
  private async checkRegistration(token: string, publicKey: string): Promise<void> {
    try {
      const devices: DeviceResponse[] = await devicesForToken(token);
      let present: boolean = false;
      for (const device of devices) {
        if (device.pubkey === publicKey) {
          present = true;
        }
      }
      native.logLine(`account: ${devices.length} devices; this key registered: ${present ? 'yes' : 'NO'}`);
    } catch (e) {
      native.logLine(`account device check failed: ${this.describeError(e as Object)}`);
    }
  }

  /** Selecting a server in the list starts connecting right away. */
  private async connectSelection(selection: RelaySelection | null): Promise<void> {
    this.selection = selection;
    const context = getContext(this) as common.Context;
    await VpnSettings.setString(context, 'selectedRelay',
      selection === null ? '' : JSON.stringify(selection));
    this.pageStack.pop();
    if (this.sessionActive()) {
      await this.stopTunnel();
    }
    await this.startTunnel();
  }

  private copyAccount(): void {
    const current: Session | null = this.session;
    if (current === null) {
      return;
    }
    const data = pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, current.account);
    pasteboard.getSystemPasteboard().setData(data).then(() => {
      this.acctToast('Account number copied');
    }).catch((err: BusinessError) => {
      hilog.warn(DOMAIN, TAG, 'clipboard failed %{public}d', err.code);
    });
  }

  /** Blue while connecting, green once a handshake exists, red on failure. */
  private phaseColor(): ResourceColor {
    if (this.phase === 'failed' || this.phase === 'lost') {
      return $r('sys.color.alert');
    }
    if (this.phase === 'connected') {
      return $r('sys.color.confirm');
    }
    if (this.phase === 'connecting' || this.busy) {
      return $r('sys.color.brand');
    }
    return $r('sys.color.font_secondary');
  }

  private sessionActive(): boolean {
    return this.phase === 'connecting' || this.phase === 'connected';
  }

  private statusTitle(): string {
    if (this.phase === 'connecting' || this.busy) {
      return 'Connecting';
    }
    if (this.phase === 'lost') {
      return 'Connection lost';
    }
    if (this.phase === 'failed') {
      return 'Connection failed';
    }
    return this.phase === 'connected' ? 'Connected' : 'Not connected';
  }

  private statusDetail(): string {
    if (this.phase === 'lost') {
      return this.errorText.length > 0 ? this.errorText :
        'The VPN was dropped. Reconnect to protect traffic again.';
    }
    if (this.phase === 'failed') {
      return this.errorText.length > 0 ? this.errorText : 'The tunnel did not come up.';
    }
    if (this.phase === 'connecting') {
      // The extension numbers every ladder attempt and knows what it is dialling; say
      // that instead of a generic "trying", so a stuck attempt is diagnosable at a glance.
      if (this.attempt > 0 && this.endpoint.length > 0) {
        const family: string = this.family.length > 0 ? this.family : 'unknown family';
        const transport: string = this.transport.length > 0 ? this.transport : 'unknown transport';
        return `attempt ${this.attempt} · ${this.endpoint} · ${family} · ${transport}`;
      }
      const target: string = this.tunnelTarget.length > 0 ? this.tunnelTarget : this.relayLabel();
      return `Trying ${target} · traffic is blocked meanwhile`;
    }
    if (this.phase === 'connected') {
      return `${formatUptime(this.uptimeMs)} · ${this.ipModeLabel()} routed`;
    }
    return 'Traffic leaves the device unprotected';
  }

  /** What the tunnel carries, in the words the cards use. */
  private ipModeLabel(): string {
    if (this.prefs.ipVersion === 'ipv6') {
      return 'IPv6 only';
    }
    if (this.prefs.ipVersion === 'auto') {
      return 'IPv4 + IPv6';
    }
    return 'IPv4 only';
  }

  private keyMismatch(): boolean {
    return this.extensionKey.length > 0 && this.uiKey.length > 0 && this.extensionKey !== this.uiKey;
  }

  // ---------------------------------------------------------------- login

  @Builder
  loginScreen() {
    Column() {
      Row() {
        Column({ space: 2 }) {
          Text('燕鸥')
            .fontSize(28)
            .fontWeight(FontWeight.Bold)
            .fontColor($r('sys.color.font_primary'))
          Text("Yàn'ōu · WireGuard client")
            .fontSize(13)
            .fontColor($r('sys.color.font_secondary'))
        }
        .alignItems(HorizontalAlign.Start)

        Blank()

        SymbolGlyph($r('sys.symbol.bolt_shield'))
          .fontSize(28)
          .fontColor([$r('sys.color.brand')])
      }
      .width('100%')
      .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 24, bottom: 16 })

      Scroll() {
        Column({ space: 12 }) {
          Column({ space: 12 }) {
            Text('Sign in')
              .fontSize(20)
              .fontWeight(FontWeight.Medium)
              .fontColor($r('sys.color.font_primary'))
            Text('Your Mullvad account number. The device key is generated here and never leaves the app.')
              .fontSize(13)
              .fontColor($r('sys.color.font_secondary'))
              .lineHeight(18)
            if (this.lastAccount.length > 0 && this.accountNumber.length === 0) {
              Row() {
                Column({ space: 2 }) {
                  Text('Continue with')
                    .fontSize(12)
                    .fontColor($r('sys.color.font_secondary'))
                  Text(maskAccount(this.lastAccount))
                    .fontSize(15)
                    .fontWeight(FontWeight.Medium)
                    .fontColor($r('sys.color.font_primary'))
                }
                .alignItems(HorizontalAlign.Start)
                .layoutWeight(1)

                Button('Sign in')
                  .type(ButtonType.Capsule)
                  .height(36)
                  .padding({ left: 18, right: 18 })
                  .fontSize(14)
                  .backgroundColor($r('sys.color.brand'))
                  .fontColor($r('sys.color.font_on_primary'))
                  .enabled(!this.loginBusy)
                  .onClick(() => {
                    this.accountNumber = this.lastAccount;
                    this.signIn();
                  })
              }
              .width('100%')
              .padding({ left: 14, right: 10, top: 8, bottom: 8 })
              .borderRadius(12)
              .backgroundColor($r('sys.color.comp_background_secondary'))
            }

            TextInput({ placeholder: '0000 0000 0000 0000', text: this.accountNumber })
              .type(InputType.Number)
              .height(48)
              .fontSize(16)
              .backgroundColor($r('sys.color.comp_background_secondary'))
              .borderRadius(12)
              .placeholderColor($r('sys.color.font_tertiary'))
              .caretColor($r('sys.color.brand'))
              .onChange((value: string) => {
                this.accountNumber = value;
              })
            Button() {
              Text(this.loginBusy ? 'Signing in…' : 'Sign in')
                .fontSize(16)
                .fontWeight(FontWeight.Medium)
                .fontColor($r('sys.color.font_on_primary'))
            }
            .type(ButtonType.Capsule)
            .width('100%')
            .height(48)
            .enabled(!this.loginBusy && this.accountNumber.trim().length >= 8)
            .opacity(this.loginBusy ? 0.6 : 1)
            .backgroundColor($r('sys.color.brand'))
            .onClick(() => {
              this.signIn();
            })
            if (this.loginError.length > 0) {
              Text(this.loginError)
                .fontSize(13)
                .fontColor($r('sys.color.alert'))
                .maxLines(3)
            }
            if (this.canManageDevices) {
              Button() {
                Text('Manage devices')
                  .fontSize(15)
                  .fontColor($r('sys.color.brand'))
              }
              .type(ButtonType.Capsule)
              .width('100%')
              .height(44)
              .backgroundColor($r('sys.color.comp_background_secondary'))
              .onClick(() => {
                this.loadDevices();
                this.pageStack.pushPath({ name: 'devices' });
              })
            }
          }
          .width('100%')
          .padding(20)
          .borderRadius(CARD_RADIUS)
          .backgroundColor($r('sys.color.comp_background_primary'))
          .alignItems(HorizontalAlign.Start)
        }
        .width('100%')
        .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, bottom: 16 })
        .alignItems(HorizontalAlign.Start)
      }
      .layoutWeight(1)
      .width('100%')
      .scrollBar(BarState.Off)
      .align(Alignment.TopStart)

      Text('Not endorsed by Mullvad VPN AB. This app is only a client.')
        .fontSize(11)
        .fontColor($r('sys.color.font_tertiary'))
        .textAlign(TextAlign.Center)
        .width('100%')
        .padding({ top: 8, bottom: 12 })
        .onClick(() => {
          this.pageStack.pushPath({ name: 'about' });
        })
    }
    .width('100%')
    .height('100%')
  }

  // ---------------------------------------------------------------- about

  @Builder
  aboutScreen() {
    Scroll() {
      Column({ space: 18 }) {
        Column({ space: 4 }) {
          Text('燕鸥')
            .fontSize(26)
            .fontWeight(FontWeight.Bold)
            .fontColor($r('sys.color.font_primary'))
          Text("Yàn'ōu · WireGuard client for HarmonyOS NEXT")
            .fontSize(13)
            .fontColor($r('sys.color.font_secondary'))
        }
        .alignItems(HorizontalAlign.Start)
        .width('100%')

        Column({ space: 6 }) {
          Text('This app is a client, not a service')
            .fontSize(16)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('sys.color.font_primary'))
          Text('It has no servers, no subscription and no account of its own. It signs in with a ' +
            'Mullvad account you already hold and connects to Mullvad relays with the WireGuard ' +
            'protocol, through the API Mullvad publishes.')
            .fontSize(14)
            .lineHeight(21)
            .fontColor($r('sys.color.font_secondary'))
        }
        .alignItems(HorizontalAlign.Start)
        .width('100%')

        Column({ space: 6 }) {
          Text('Why it exists')
            .fontSize(16)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('sys.color.font_primary'))
          Text('Mullvad does not provide an official client for HarmonyOS. 燕鸥 is an independent, ' +
            'third-party client for HarmonyOS NEXT, and it is not affiliated with, endorsed by or ' +
            'supported by Mullvad VPN AB.')
            .fontSize(14)
            .lineHeight(21)
            .fontColor($r('sys.color.font_secondary'))
        }
        .alignItems(HorizontalAlign.Start)
        .width('100%')

        Column({ space: 6 }) {
          Text('If anyone sold you a subscription')
            .fontSize(16)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('sys.color.font_primary'))
          Text('This app never sells subscriptions or accounts. If anyone sold you "Mullvad access", ' +
            'a subscription or an account through this app or through any other third party, you ' +
            'were scammed. Mullvad accounts are sold only by Mullvad, at mullvad.net.')
            .fontSize(14)
            .lineHeight(21)
            .fontColor($r('sys.color.font_secondary'))
        }
        .alignItems(HorizontalAlign.Start)
        .width('100%')

        Column({ space: 6 }) {
          Text('Terms')
            .fontSize(16)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('sys.color.font_primary'))
          Text('There are no terms of service: this is not a service. The app is provided as is, ' +
            'under the GPL-3.0-or-later licence, and based on the open-source client from ' +
            'mullvad/mullvadvpn-app. Your Mullvad account is governed by Mullvad\'s terms, not by ' +
            'this app.')
            .fontSize(14)
            .lineHeight(21)
            .fontColor($r('sys.color.font_secondary'))
        }
        .alignItems(HorizontalAlign.Start)
        .width('100%')

        Button('Close')
          .type(ButtonType.Capsule)
          .height(40)
          .width('100%')
          .fontSize(15)
          .backgroundColor($r('sys.color.comp_background_secondary'))
          .fontColor($r('sys.color.brand'))
          .onClick(() => {
            this.pageStack.pop();
          })
      }
      .width('100%')
      .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 12, bottom: 24 })
      .alignItems(HorizontalAlign.Start)
    }
    .width('100%')
    .height('100%')
    .scrollBar(BarState.Off)
    .align(Alignment.TopStart)
  }

  // ---------------------------------------------------------------- main

  @Builder
  mainScreen() {
    Column() {
      Row() {
        Column({ space: 2 }) {
          Text('燕鸥')
            .fontSize(22)
            .fontWeight(FontWeight.Bold)
            .fontColor($r('sys.color.font_primary'))
          Text(this.connected ? 'Tunnel active' :
            (this.phase === 'lost' ? 'Connection lost' : 'Not connected'))
            .fontSize(12)
            .fontColor($r('sys.color.font_secondary'))
        }
        .alignItems(HorizontalAlign.Start)

        Blank()

        Row({ space: 18 }) {
          SymbolGlyph($r('sys.symbol.person'))
            .fontSize(22)
            .fontColor([$r('sys.color.font_secondary')])
            .onClick(() => {
              this.loadAccountExpiry();
              this.loadDevices();
              this.pageStack.pushPath({ name: 'account' });
            })
          SymbolGlyph($r('sys.symbol.gearshape'))
            .fontSize(22)
            .fontColor([$r('sys.color.font_secondary')])
            .onClick(() => {
              this.pageStack.pushPath({ name: 'settings' });
            })
        }
      }
      .width('100%')
      .height(64)
      .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER })
      .alignItems(VerticalAlign.Center)

      // Outside the card, so a lost or failed tunnel stays visible while the page scrolls.
      if (this.phase === 'lost') {
        Row({ space: 8 }) {
          SymbolGlyph($r('sys.symbol.exclamationmark_triangle'))
            .fontSize(18)
            .fontColor([$r('sys.color.alert')])
          Text(this.retrying ? 'Connection lost — reconnecting…' : 'Connection lost')
            .fontSize(13)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('sys.color.alert'))
            .layoutWeight(1)
          Text('Reconnect')
            .fontSize(13)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('sys.color.brand'))
            .padding({ left: 8, top: 4, bottom: 4 })
            .onClick(() => {
              this.reconnectTunnel();
            })
        }
        .width('100%')
        .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 10, bottom: 10 })
        .backgroundColor($r('sys.color.comp_background_secondary'))
        .alignItems(VerticalAlign.Center)
      }

      Scroll() {
        Column({ space: 12 }) {
          Column({ space: 12 }) {
            Stack() {
              Circle()
                .width(96)
                .height(96)
                .fill(this.sessionActive() || this.phase === 'failed' || this.phase === 'lost' ?
                  this.phaseColor() : $r('sys.color.comp_background_secondary'))
                .opacity(this.sessionActive() || this.phase === 'failed' || this.phase === 'lost' ? 0.14 : 1)
              SymbolGlyph($r('sys.symbol.power'))
                .fontSize(40)
                .fontColor([this.phaseColor()])
            }
            .width(96)
            .height(96)

            Text(this.statusTitle())
              .fontSize(20)
              .fontWeight(FontWeight.Medium)
              .fontColor(this.sessionActive() || this.phase === 'failed' || this.phase === 'lost' ?
                this.phaseColor() : $r('sys.color.font_primary'))

            Text(this.statusDetail())
              .fontSize(14)
              .fontColor(this.phase === 'failed' || this.phase === 'lost' ?
                $r('sys.color.alert') : $r('sys.color.font_secondary'))
              .textAlign(TextAlign.Center)
              .maxLines(3)
              .textOverflow({ overflow: TextOverflow.Ellipsis })

            // "Automatic" hides which relay was picked; once a candidate answers, name it.
            if (this.sessionActive() && this.tunnelTarget.length > 0) {
              Text(this.tunnelTarget)
                .fontSize(13)
                .fontColor($r('sys.color.brand'))
                .textAlign(TextAlign.Center)
            }

            // Measured by the extension (device up → handshake), 0 means it is not known.
            if (this.phase === 'connected' && this.handshakeMs > 0) {
              Text(`${this.handshakeMs} ms handshake`)
                .fontSize(12)
                .fontColor($r('sys.color.font_secondary'))
                .textAlign(TextAlign.Center)
            }

            if (this.sessionActive()) {
              Row() {
                Column({ space: 2 }) {
                  Text(formatBytes(this.rxBytes))
                    .fontSize(20)
                    .fontWeight(FontWeight.Medium)
                    .fontColor($r('sys.color.font_primary'))
                  Text('received')
                    .fontSize(11)
                    .fontColor($r('sys.color.font_secondary'))
                }
                .layoutWeight(1)

                Column({ space: 2 }) {
                  Text(formatBytes(this.txBytes))
                    .fontSize(20)
                    .fontWeight(FontWeight.Medium)
                    .fontColor($r('sys.color.font_primary'))
                  Text('sent')
                    .fontSize(11)
                    .fontColor($r('sys.color.font_secondary'))
                }
                .layoutWeight(1)

                Column({ space: 2 }) {
                  Text(`${this.packets}`)
                    .fontSize(20)
                    .fontWeight(FontWeight.Medium)
                    .fontColor($r('sys.color.font_primary'))
                  Text('captured')
                    .fontSize(11)
                    .fontColor($r('sys.color.font_secondary'))
                }
                .layoutWeight(1)
              }
              .width('100%')
              .margin({ top: 12 })
            }

            if (this.sessionActive() || this.phase === 'failed' || this.phase === 'lost') {
              Row({ space: 4 }) {
                Text('Details')
                  .fontSize(12)
                  .fontColor($r('sys.color.font_tertiary'))
                SymbolGlyph($r('sys.symbol.chevron_right'))
                  .fontSize(14)
                  .fontColor([$r('sys.color.font_tertiary')])
              }
              .margin({ top: 4 })
            }
          }
          .width('100%')
          .padding({ top: 28, bottom: 28, left: 20, right: 20 })
          .borderRadius(CARD_RADIUS)
          .backgroundColor($r('sys.color.comp_background_primary'))
          .alignItems(HorizontalAlign.Center)
          .onClick(() => {
            if (this.sessionActive() || this.phase === 'failed' || this.phase === 'lost') {
              this.detailsVisible = true;
            }
          })
          .bindSheet($$this.detailsVisible, this.connectionSheet(), {
            height: SheetSize.LARGE,
            showClose: true,
            title: { title: 'Connection details' },
            backgroundColor: $r('sys.color.background_secondary')
          })

          if (this.keyMismatch()) {
            Row({ space: 8 }) {
              SymbolGlyph($r('sys.symbol.exclamationmark_triangle'))
                .fontSize(18)
                .fontColor([$r('sys.color.alert')])
              Text('The tunnel process uses a different device key than the one this account registered.')
                .fontSize(13)
                .fontColor($r('sys.color.alert'))
                .layoutWeight(1)
            }
            .width('100%')
            .padding(16)
            .borderRadius(CARD_RADIUS)
            .backgroundColor($r('sys.color.comp_background_primary'))
          }

          Column() {
            Row() {
              Text('Servers')
                .fontSize(15)
                .fontColor($r('sys.color.font_primary'))
              Blank()
              Text(this.sessionActive() && this.tunnelTarget.length > 0 ?
                this.tunnelTarget : this.relayLabel())
                .fontSize(13)
                .fontColor($r('sys.color.font_tertiary'))
              SymbolGlyph($r('sys.symbol.chevron_right'))
                .fontSize(16)
                .fontColor([$r('sys.color.font_tertiary')])
                .margin({ left: 4 })
            }
            .width('100%')
            .height(48)
            .onClick(() => {
              this.openServers();
            })

            // The entry stays the "Servers" row; multihop only adds the second hop here.
            if (this.prefs.multihop) {
              Divider()
                .strokeWidth(0.5)
                .color($r('sys.color.comp_divider'))
              Row() {
                Text('Exit')
                  .fontSize(15)
                  .fontColor($r('sys.color.font_primary'))
                Blank()
                Text(this.exitSelection === null ? 'Not selected' : this.exitLabel())
                  .fontSize(13)
                  .fontColor(this.exitSelection === null ?
                    $r('sys.color.font_tertiary') : $r('sys.color.brand'))
                  .maxLines(1)
                  .textOverflow({ overflow: TextOverflow.Ellipsis })
                SymbolGlyph($r('sys.symbol.chevron_right'))
                  .fontSize(16)
                  .fontColor([$r('sys.color.font_tertiary')])
                  .margin({ left: 4 })
              }
              .width('100%')
              .height(48)
              .onClick(() => {
                this.openServers('exit');
              })
            }

          }
          .width('100%')
          .padding({ left: 16, right: 16 })
          .borderRadius(CARD_RADIUS)
          .backgroundColor($r('sys.color.comp_background_primary'))

          Column({ space: 8 }) {
            Text('Tunnel configuration')
              .fontSize(13)
              .fontWeight(FontWeight.Medium)
              .fontColor($r('sys.color.font_secondary'))
            Text(`vNIC ${this.session?.ipv4 ?? '-'} · MTU ${this.effectiveMtu()} · ` +
              `DNS ${this.dnsLabel()}`)
              .fontSize(13)
              .fontColor($r('sys.color.font_tertiary'))
            Text(`${this.ipModeLabel()} · kill switch ${this.prefs.killSwitch ? 'on' : 'off'}`)
              .fontSize(13)
              .fontColor($r('sys.color.font_tertiary'))
            Text(this.multihopSummary())
              .fontSize(13)
              .fontColor(this.multihopActive() ?
                $r('sys.color.brand') : $r('sys.color.font_tertiary'))
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .width('100%')
          .padding(16)
          .borderRadius(CARD_RADIUS)
          .backgroundColor($r('sys.color.comp_background_primary'))
          .alignItems(HorizontalAlign.Start)
        }
        .width('100%')
        .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 4, bottom: 16 })
        .alignItems(HorizontalAlign.Start)
      }
      .layoutWeight(1)
      .width('100%')
      .scrollBar(BarState.Off)
      .align(Alignment.TopStart)

      Row({ space: 8 }) {
        if (this.sessionActive()) {
          Button() {
            Text('Reconnect')
              .fontSize(15)
              .fontWeight(FontWeight.Medium)
              .fontColor($r('sys.color.font_primary'))
          }
          .type(ButtonType.Capsule)
          .layoutWeight(1)
          .height(48)
          .enabled(!this.busy)
          .opacity(this.busy ? 0.6 : 1)
          .backgroundColor($r('sys.color.comp_background_secondary'))
          .onClick(() => {
            this.reconnectTunnel();
          })
        }

        Button() {
          Row({ space: 8 }) {
            SymbolGlyph($r('sys.symbol.power'))
              .fontSize(20)
              .fontColor([this.sessionActive() ? $r('sys.color.font_primary') : $r('sys.color.font_on_primary')])
            Text(this.sessionActive() ? 'Disconnect' : 'Connect')
              .fontSize(16)
              .fontWeight(FontWeight.Medium)
              .fontColor(this.sessionActive() ? $r('sys.color.font_primary') : $r('sys.color.font_on_primary'))
          }
        }
        .type(ButtonType.Capsule)
        .layoutWeight(1)
        .height(48)
        .enabled(!this.busy)
        .opacity(this.busy ? 0.6 : 1)
        .backgroundColor(this.sessionActive() ? $r('sys.color.comp_background_secondary') : $r('sys.color.brand'))
        .onClick(() => {
          this.toggleTunnel();
        })
      }
      .width('100%')
      .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, bottom: PAGE_GUTTER })
    }
    .width('100%')
    .height('100%')
  }

  /**
   * Read-only mirror of what the extension last published. Opened from the hero card;
   * every value here comes from state and nothing on the sheet changes the connection.
   */
  @Builder
  connectionSheet() {
    Scroll() {
      Column({ space: 12 }) {
        Column() {
          Row({ space: 12 }) {
            Text('Status')
              .fontSize(14)
              .fontColor($r('sys.color.font_secondary'))
            Text(this.statusTitle())
              .fontSize(14)
              .fontWeight(FontWeight.Medium)
              .fontColor(this.phaseColor())
              .layoutWeight(1)
              .textAlign(TextAlign.End)
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .width('100%')
          .constraintSize({ minHeight: 38 })
          .alignItems(VerticalAlign.Center)

          Row({ space: 12 }) {
            Text('Relay')
              .fontSize(14)
              .fontColor($r('sys.color.font_secondary'))
            Text(this.tunnelTarget.length > 0 ? this.tunnelTarget : this.relayLabel())
              .fontSize(14)
              .fontColor($r('sys.color.font_primary'))
              .layoutWeight(1)
              .textAlign(TextAlign.End)
              .maxLines(2)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .width('100%')
          .constraintSize({ minHeight: 38 })
          .alignItems(VerticalAlign.Center)

          Row({ space: 12 }) {
            Text('Endpoint')
              .fontSize(14)
              .fontColor($r('sys.color.font_secondary'))
            Text(this.endpoint.length > 0 ? this.endpoint : '—')
              .fontSize(14)
              .fontColor($r('sys.color.font_primary'))
              .layoutWeight(1)
              .textAlign(TextAlign.End)
              .maxLines(2)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .width('100%')
          .constraintSize({ minHeight: 38 })
          .alignItems(VerticalAlign.Center)

          Row({ space: 12 }) {
            Text('Transport')
              .fontSize(14)
              .fontColor($r('sys.color.font_secondary'))
            Text(this.transport.length > 0 ? this.transport : '—')
              .fontSize(14)
              .fontColor($r('sys.color.font_primary'))
              .layoutWeight(1)
              .textAlign(TextAlign.End)
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .width('100%')
          .constraintSize({ minHeight: 38 })
          .alignItems(VerticalAlign.Center)

          Row({ space: 12 }) {
            Text('Address family')
              .fontSize(14)
              .fontColor($r('sys.color.font_secondary'))
            Text(this.family.length > 0 ? this.family : '—')
              .fontSize(14)
              .fontColor($r('sys.color.font_primary'))
              .layoutWeight(1)
              .textAlign(TextAlign.End)
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .width('100%')
          .constraintSize({ minHeight: 38 })
          .alignItems(VerticalAlign.Center)

          Row({ space: 12 }) {
            Text('Handshake')
              .fontSize(14)
              .fontColor($r('sys.color.font_secondary'))
            Text(this.handshakeMs > 0 ? `${this.handshakeMs} ms` : '—')
              .fontSize(14)
              .fontColor($r('sys.color.font_primary'))
              .layoutWeight(1)
              .textAlign(TextAlign.End)
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .width('100%')
          .constraintSize({ minHeight: 38 })
          .alignItems(VerticalAlign.Center)

          Row({ space: 12 }) {
            Text('Uptime')
              .fontSize(14)
              .fontColor($r('sys.color.font_secondary'))
            Text(this.uptimeMs > 0 ? formatUptime(this.uptimeMs) : '—')
              .fontSize(14)
              .fontColor($r('sys.color.font_primary'))
              .layoutWeight(1)
              .textAlign(TextAlign.End)
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .width('100%')
          .constraintSize({ minHeight: 38 })
          .alignItems(VerticalAlign.Center)

          Row({ space: 12 }) {
            Text('Received')
              .fontSize(14)
              .fontColor($r('sys.color.font_secondary'))
            Text(formatBytes(this.rxBytes))
              .fontSize(14)
              .fontColor($r('sys.color.font_primary'))
              .layoutWeight(1)
              .textAlign(TextAlign.End)
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .width('100%')
          .constraintSize({ minHeight: 38 })
          .alignItems(VerticalAlign.Center)

          Row({ space: 12 }) {
            Text('Sent')
              .fontSize(14)
              .fontColor($r('sys.color.font_secondary'))
            Text(formatBytes(this.txBytes))
              .fontSize(14)
              .fontColor($r('sys.color.font_primary'))
              .layoutWeight(1)
              .textAlign(TextAlign.End)
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .width('100%')
          .constraintSize({ minHeight: 38 })
          .alignItems(VerticalAlign.Center)

          Row({ space: 12 }) {
            Text('Protector fd')
              .fontSize(14)
              .fontColor($r('sys.color.font_secondary'))
            Text(this.protectedFd >= 0 ? `${this.protectedFd}` : '—')
              .fontSize(14)
              .fontColor($r('sys.color.font_primary'))
              .layoutWeight(1)
              .textAlign(TextAlign.End)
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .width('100%')
          .constraintSize({ minHeight: 38 })
          .alignItems(VerticalAlign.Center)

          Row({ space: 12 }) {
            Text('Continuous task')
              .fontSize(14)
              .fontColor($r('sys.color.font_secondary'))
            Text(this.keepAlive ? 'active' : 'off')
              .fontSize(14)
              .fontColor($r('sys.color.font_primary'))
              .layoutWeight(1)
              .textAlign(TextAlign.End)
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          }
          .width('100%')
          .constraintSize({ minHeight: 38 })
          .alignItems(VerticalAlign.Center)
        }
        .width('100%')
        .padding({ left: 16, right: 16 })
        .borderRadius(CARD_RADIUS)
        .backgroundColor($r('sys.color.comp_background_primary'))

        Button('View diagnostics')
          .type(ButtonType.Capsule)
          .width('100%')
          .height(44)
          .fontSize(15)
          .fontColor($r('sys.color.font_primary'))
          .backgroundColor($r('sys.color.comp_background_secondary'))
          .onClick(() => {
            this.pageStack.pushPath({ name: 'logs' });
            this.detailsVisible = false;
          })
      }
      .width('100%')
      .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 4, bottom: 24 })
      .alignItems(HorizontalAlign.Start)
    }
    .width('100%')
    .height('100%')
    .scrollBar(BarState.Off)
    .align(Alignment.TopStart)
  }

  // ---------------------------------------------------------------- devices

  @Builder
  devicesScreen() {
    Column() {
      Text('A Mullvad account can have five devices. Remove one to free a slot for this tablet.')
        .fontSize(13)
        .fontColor($r('sys.color.font_secondary'))
        .lineHeight(18)
        .padding({ left: 20, right: 20, top: 8, bottom: 12 })

      if (this.devicesBusy) {
        LoadingProgress()
          .width(40)
          .height(40)
          .color($r('sys.color.brand'))
          .margin({ top: 24 })
      }

      if (this.devicesError.length > 0) {
        Text(this.devicesError)
          .fontSize(13)
          .fontColor($r('sys.color.alert'))
          .padding({ left: 20, right: 20, top: 8 })
      }

      Scroll() {
        Column() {
          ForEach(this.devices, (device: DeviceResponse) => {
            Column() {
              Row() {
                Column({ space: 4 }) {
                  Text(device.name)
                    .fontSize(15)
                    .fontWeight(FontWeight.Medium)
                    .fontColor($r('sys.color.font_primary'))
                  Text(`${device.ipv4_address} · added ${formatDate(device.created)}`)
                    .fontSize(12)
                    .fontColor($r('sys.color.font_secondary'))
                }
                .alignItems(HorizontalAlign.Start)
                .layoutWeight(1)

                if (this.removingId === device.id) {
                  LoadingProgress()
                    .width(24)
                    .height(24)
                    .color($r('sys.color.brand'))
                } else {
                  Button() {
                    SymbolGlyph($r('sys.symbol.trash'))
                      .fontSize(18)
                      .fontColor([$r('sys.color.alert')])
                  }
                  .type(ButtonType.Circle)
                  .width(40)
                  .height(40)
                  .backgroundColor($r('sys.color.comp_background_secondary'))
                  .onClick(() => {
                    this.confirmRemove(device);
                  })
                }
              }
              .width('100%')
              .padding({ top: 12, bottom: 12 })
            }
            .width('100%')
          }, (device: DeviceResponse) => device.id)
        }
        .width('100%')
        .padding({ left: 16, right: 16 })
      }
      .layoutWeight(1)
      .align(Alignment.TopStart)

      Row() {
        Button('Refresh')
          .type(ButtonType.Capsule)
          .height(44)
          .width('100%')
          .backgroundColor($r('sys.color.comp_background_secondary'))
          .fontColor($r('sys.color.font_primary'))
          .enabled(!this.devicesBusy)
          .onClick(() => {
            this.loadDevices();
          })
      }
      .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, bottom: PAGE_GUTTER })
    }
    .width('100%')
    .height('100%')
  }

  // ---------------------------------------------------------------- servers

  // ---------------------------------------------------- server browser helpers

  /** Checkmark state: in exit mode it compares the exit, otherwise the entry selection. */
  private srvIsSelected(relay: RelayItem): boolean {
    if (this.serverMode === 'exit') {
      return this.exitSelection !== null && this.exitSelection.hostname === relay.hostname;
    }
    return this.selection !== null && this.selection.hostname === relay.hostname;
  }

  /**
   * One row, two meanings: in entry mode it connects through the relay, in exit mode it
   * only saves the exit and rebuilds the tunnel if one is up.
   */
  private async srvTapRelay(relay: RelayItem): Promise<void> {
    if (this.serverMode === 'exit') {
      await this.selectExitRelay(relay);
    } else {
      await this.selectRelay(relay);
    }
  }

  /** True when the relay passes the active filter chip. Search is applied separately. */
  private srvMatchesFilter(relay: RelayItem): boolean {
    if (this.srvFilter === 'daita') {
      return relay.daita;
    }
    if (this.srvFilter === 'owned') {
      return relay.owned;
    }
    if (this.srvFilter === 'recent') {
      return this.recentHostnames().includes(relay.hostname);
    }
    return true;
  }

  /** Search results narrowed by the chip: every list in the browser reads this. */
  private srvFilteredRelays(): RelayItem[] {
    return this.filteredRelays().filter((relay: RelayItem) => this.srvMatchesFilter(relay));
  }

  private srvSearchQuery(): string {
    return this.search.trim().toLowerCase();
  }

  /** Countries present in the filtered list, most used first (same order as before). */
  private srvCountries(): string[] {
    const usage = this.usageMap();
    const names: string[] = [];
    for (const relay of this.srvFilteredRelays()) {
      const name: string = relay.country.length > 0 ? relay.country : relay.location;
      if (!names.includes(name)) {
        names.push(name);
      }
    }
    names.sort((a: string, b: string) => {
      const left: number = usage.get(a) ?? 0;
      const right: number = usage.get(b) ?? 0;
      if (left !== right) {
        return right - left;
      }
      return a < b ? -1 : (a > b ? 1 : 0);
    });
    return names;
  }

  private srvRelaysInCountry(country: string): RelayItem[] {
    return this.srvFilteredRelays().filter((relay: RelayItem) =>
      (relay.country.length > 0 ? relay.country : relay.location) === country);
  }

  /** City names inside one country, alphabetical, for the expanded country. */
  private srvCitiesInCountry(country: string): string[] {
    const cities: string[] = [];
    for (const relay of this.srvRelaysInCountry(country)) {
      if (!cities.includes(relay.city)) {
        cities.push(relay.city);
      }
    }
    cities.sort((a: string, b: string) => a < b ? -1 : (a > b ? 1 : 0));
    return cities;
  }

  private srvRelaysInCity(country: string, city: string): RelayItem[] {
    return this.srvRelaysInCountry(country).filter((relay: RelayItem) => relay.city === city);
  }

  private srvFavouriteHostnames(): string[] {
    try {
      const parsed: string[] = JSON.parse(this.srvFavouritesJson) as string[];
      if (!Array.isArray(parsed)) {
        return [];
      }
      return parsed;
    } catch (e) {
      return [];
    }
  }

  private srvIsFavourite(hostname: string): boolean {
    return this.srvFavouriteHostnames().includes(hostname);
  }

  /** Favourites are matched against the filtered list, so chips still narrow them. */
  private srvFavouriteRelays(): RelayItem[] {
    const names: string[] = this.srvFavouriteHostnames();
    const items: RelayItem[] = [];
    for (const relay of this.srvFilteredRelays()) {
      if (names.includes(relay.hostname)) {
        items.push(relay);
      }
    }
    return items;
  }

  private async srvLoadFavourites(): Promise<void> {
    const raw: string = await VpnSettings.getString(getContext(this) as common.Context,
      'favourites', '[]');
    try {
      const parsed: string[] = JSON.parse(raw) as string[];
      this.srvFavouritesJson = Array.isArray(parsed) ? JSON.stringify(parsed) : '[]';
    } catch (e) {
      this.srvFavouritesJson = '[]';
    }
  }

  private srvToggleFavourite(relay: RelayItem): void {
    const names: string[] = this.srvFavouriteHostnames();
    const index: number = names.indexOf(relay.hostname);
    if (index >= 0) {
      names.splice(index, 1);
    } else {
      names.unshift(relay.hostname);
    }
    this.srvFavouritesJson = JSON.stringify(names);
    this.srvPersistFavourites();
  }

  private async srvPersistFavourites(): Promise<void> {
    try {
      await VpnSettings.setString(getContext(this) as common.Context, 'favourites',
        this.srvFavouritesJson);
    } catch (e) {
      hilog.warn(DOMAIN, TAG, 'favourite persist failed');
    }
  }

  private srvRecentRelays(): RelayItem[] {
    const items: RelayItem[] = [];
    const available: RelayItem[] = this.srvFilteredRelays();
    for (const hostname of this.recentHostnames()) {
      for (const relay of available) {
        if (relay.hostname === hostname) {
          items.push(relay);
          break;
        }
      }
    }
    return items;
  }

  private srvMatchingCountries(): string[] {
    const query: string = this.srvSearchQuery();
    if (query.length === 0) {
      return [];
    }
    return this.srvCountries().filter((country: string) => country.toLowerCase().includes(query));
  }

  /** One representative relay per matching city; the city row connects to its country. */
  private srvMatchingCities(): RelayItem[] {
    const query: string = this.srvSearchQuery();
    if (query.length === 0) {
      return [];
    }
    const seen: string[] = [];
    const representatives: RelayItem[] = [];
    for (const relay of this.srvFilteredRelays()) {
      if (!relay.city.toLowerCase().includes(query)) {
        continue;
      }
      const key: string = `${relay.country}|${relay.city}`;
      if (!seen.includes(key)) {
        seen.push(key);
        representatives.push(relay);
      }
    }
    return representatives;
  }

  private srvMatchingRelays(): RelayItem[] {
    const query: string = this.srvSearchQuery();
    if (query.length === 0) {
      return [];
    }
    return this.srvFilteredRelays().filter((relay: RelayItem) =>
      relay.hostname.toLowerCase().includes(query));
  }

  @Builder
  relayRow(relay: RelayItem) {
    Row({ space: 8 }) {
      // Tapping the relay connects; the favourite icon is a sibling so it never does.
      Row({ space: 8 }) {
        Column({ space: 2 }) {
          Text(`${relay.city}, ${relay.country}`)
            .fontSize(15)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('sys.color.font_primary'))
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
          Text(relay.hostname)
            .fontSize(12)
            .fontColor($r('sys.color.font_secondary'))
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
        }
        .alignItems(HorizontalAlign.Start)
        .layoutWeight(1)

        if (relay.daita) {
          Text('DAITA')
            .fontSize(11)
            .fontColor($r('sys.color.brand'))
        }

        if (this.srvIsSelected(relay)) {
          SymbolGlyph($r('sys.symbol.bolt_shield'))
            .fontSize(16)
            .fontColor([$r('sys.color.brand')])
        }
      }
      .layoutWeight(1)
      .height(56)
      .onClick(() => {
        this.srvTapRelay(relay);
      })

      // The checkmark doubles as the favourite toggle: tap it to pin or unpin a relay.
      SymbolGlyph($r('sys.symbol.checkmark'))
        .fontSize(16)
        .fontColor([this.srvIsFavourite(relay.hostname) ?
          $r('sys.color.brand') : $r('sys.color.font_tertiary')])
        .padding(8)
        .borderRadius(16)
        .backgroundColor(this.srvIsFavourite(relay.hostname) ?
          $r('sys.color.comp_background_primary') : Color.Transparent)
        .onClick(() => {
          this.srvToggleFavourite(relay);
        })
    }
    .width('100%')
    .height(56)
  }

  /** A country you can connect to without opening it: the pill starts the attempt. */
  @Builder
  countryRow(country: string) {
    Row({ space: 10 }) {
      Row({ space: 6 }) {
        Column({ space: 2 }) {
          Text(country)
            .fontSize(15)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('sys.color.font_primary'))
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
          Text(`${this.srvRelaysInCountry(country).length} relays`)
            .fontSize(11)
            .fontColor($r('sys.color.font_secondary'))
        }
        .alignItems(HorizontalAlign.Start)
        .layoutWeight(1)

        // Usage is a compact badge so the row stays scannable; zero uses show nothing.
        if (this.usageCount(country) > 0) {
          Text(`${this.usageCount(country)}×`)
            .fontSize(11)
            .fontColor($r('sys.color.brand'))
            .height(20)
            .lineHeight(20)
            .padding({ left: 8, right: 8 })
            .borderRadius(10)
            .backgroundColor($r('sys.color.comp_background_secondary'))
            .textAlign(TextAlign.Center)
        }

        // In exit mode an exit is always a concrete relay: the country's "Auto" shortcut
        // has no meaning there, so the row only expands to its relays.
        if (this.serverMode === 'entry' && this.selection !== null &&
          this.selection.kind === 'country' && this.selection.country === country) {
          SymbolGlyph($r('sys.symbol.checkmark'))
            .fontSize(16)
            .fontColor([$r('sys.color.brand')])
        }

        SymbolGlyph($r('sys.symbol.chevron_right'))
          .fontSize(16)
          .fontColor([$r('sys.color.font_tertiary')])
          .rotate({ angle: this.expandedCountry === country ? 90 : 0 })
      }
      .layoutWeight(1)
      .height(56)
      .onClick(() => {
        this.expandedCountry = this.expandedCountry === country ? '' : country;
      })

      if (this.serverMode === 'entry') {
        Button() {
          Text('Auto')
            .fontSize(13)
            .fontColor($r('sys.color.brand'))
        }
        .type(ButtonType.Capsule)
        .height(32)
        .padding({ left: 14, right: 14 })
        .backgroundColor($r('sys.color.comp_background_secondary'))
        .onClick(() => {
          this.selectCountry(country);
        })
      }
    }
    .width('100%')
  }

  @Builder
  automaticRow() {
    Row() {
      Column({ space: 2 }) {
        Text(this.serverMode === 'exit' ? 'No exit' : 'Automatic')
          .fontSize(15)
          .fontWeight(FontWeight.Medium)
          .fontColor($r('sys.color.font_primary'))
        Text(this.serverMode === 'exit' ?
          'Single hop · traffic leaves through the entry relay' :
          'Any country · tries relays until one answers')
          .fontSize(11)
          .fontColor($r('sys.color.font_secondary'))
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)

      if (this.serverMode === 'exit' ? this.exitSelection === null : this.selection === null) {
        SymbolGlyph($r('sys.symbol.checkmark'))
          .fontSize(18)
          .fontColor([$r('sys.color.brand')])
      } else {
        SymbolGlyph($r('sys.symbol.power'))
          .fontSize(16)
          .fontColor([$r('sys.color.font_tertiary')])
      }
    }
    .width('100%')
    .height(56)
    .onClick(() => {
      if (this.serverMode === 'exit') {
        this.clearExit();
      } else {
        this.selectAutomatic();
      }
    })
  }

  /** Pinned at the very top of the browser; only while a tunnel is up. */
  @Builder
  srvConnectedCard() {
    Row({ space: 12 }) {
      SymbolGlyph($r('sys.symbol.bolt_shield'))
        .fontSize(22)
        .fontColor([$r('sys.color.brand')])

      Column({ space: 2 }) {
        Text(`Connected to ${this.tunnelTarget}`)
          .fontSize(13)
          .fontWeight(FontWeight.Medium)
          .fontColor($r('sys.color.font_primary'))
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
        Text('Traffic is protected by the tunnel')
          .fontSize(11)
          .fontColor($r('sys.color.font_secondary'))
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)

      Button() {
        Text('Reconnect')
          .fontSize(12)
          .fontColor($r('sys.color.font_primary'))
      }
      .type(ButtonType.Capsule)
      .height(32)
      .padding({ left: 12, right: 12 })
      .backgroundColor($r('sys.color.comp_background_secondary'))
      .enabled(!this.busy)
      .opacity(this.busy ? 0.6 : 1)
      .onClick(() => {
        this.reconnectTunnel();
      })
    }
    .width('100%')
    .padding(12)
    .borderRadius(CARD_RADIUS)
    .backgroundColor($r('sys.color.comp_background_primary'))
  }

  /** Compact capsule used for the All / DAITA / Owned / Recent filters. */
  @Builder
  srvFilterChip(label: string, value: string) {
    Button(label)
      .type(ButtonType.Capsule)
      .height(32)
      .padding({ left: 14, right: 14 })
      .fontSize(12)
      .fontWeight(FontWeight.Medium)
      .fontColor(this.srvFilter === value ? $r('sys.color.font_on_primary') :
        $r('sys.color.font_secondary'))
      .backgroundColor(this.srvFilter === value ? $r('sys.color.brand') :
        $r('sys.color.comp_background_secondary'))
      .onClick(() => {
        this.srvFilter = value;
      })
  }

  @Builder
  srvSectionHeader(title: string) {
    Text(title)
      .fontSize(13)
      .fontWeight(FontWeight.Medium)
      .fontColor($r('sys.color.font_secondary'))
      .margin({ left: 4, top: 8, bottom: 2 })
  }

  @Builder
  srvDivider() {
    Divider()
      .strokeWidth(0.5)
      .color($r('sys.color.comp_divider'))
      .margin({ top: 6, bottom: 6 })
  }

  /** Small sub-header above each city group inside an expanded country. */
  @Builder
  srvCityHeader(city: string, count: number) {
    Text(`${city} · ${count} ${count === 1 ? 'relay' : 'relays'}`)
      .fontSize(11)
      .fontWeight(FontWeight.Medium)
      .fontColor($r('sys.color.font_tertiary'))
      .margin({ left: 12, top: 6, bottom: 2 })
  }

  /** Indents a relay under its city sub-header without changing `relayRow` itself. */
  @Builder
  srvCityRelayRow(relay: RelayItem) {
    Row() {
      this.relayRow(relay)
    }
    .width('100%')
    .padding({ left: 12 })
  }

  /** Country hit in the search results: connects to any relay there, as before. */
  @Builder
  srvSearchCountryRow(country: string) {
    Row() {
      Column({ space: 2 }) {
        Text(country)
          .fontSize(15)
          .fontWeight(FontWeight.Medium)
          .fontColor($r('sys.color.font_primary'))
        Text(`Connect to any relay · ${this.srvRelaysInCountry(country).length} available`)
          .fontSize(11)
          .fontColor($r('sys.color.font_secondary'))
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)

      if (this.selection !== null && this.selection.kind === 'country' &&
        this.selection.country === country) {
        SymbolGlyph($r('sys.symbol.checkmark'))
          .fontSize(18)
          .fontColor([$r('sys.color.brand')])
      } else {
        SymbolGlyph($r('sys.symbol.power'))
          .fontSize(16)
          .fontColor([$r('sys.color.font_tertiary')])
      }
    }
    .width('100%')
    .height(56)
    .onClick(() => {
      this.selectCountry(country);
    })
  }

  /** City hit in the search results: selecting it lets the country pick the relay. */
  @Builder
  srvSearchCityRow(relay: RelayItem) {
    Row() {
      Column({ space: 2 }) {
        Text(relay.city)
          .fontSize(15)
          .fontWeight(FontWeight.Medium)
          .fontColor($r('sys.color.font_primary'))
        Text(`${relay.country} · ${this.srvRelaysInCity(relay.country, relay.city).length} relays`)
          .fontSize(11)
          .fontColor($r('sys.color.font_secondary'))
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)

      SymbolGlyph($r('sys.symbol.power'))
        .fontSize(16)
        .fontColor([$r('sys.color.font_tertiary')])
    }
    .width('100%')
    .height(56)
    .onClick(() => {
      this.selectCountry(relay.country);
    })
  }

  /** Search is grouped into Countries / Cities / Relays instead of one flat list. */
  @Builder
  srvSearchResults() {
    Column() {
      // An exit is one specific relay: the country and city shortcuts only make sense
      // while choosing the entry, so exit mode searches relays only.
      if (this.serverMode === 'entry' && this.srvMatchingCountries().length > 0) {
        this.srvSectionHeader('Countries')
        ForEach(this.srvMatchingCountries(), (country: string) => {
          this.srvSearchCountryRow(country)
        }, (country: string) => `srv-c-${country}-${this.srvFilter}`)
        this.srvDivider()
      }

      if (this.serverMode === 'entry' && this.srvMatchingCities().length > 0) {
        this.srvSectionHeader('Cities')
        ForEach(this.srvMatchingCities(), (relay: RelayItem) => {
          this.srvSearchCityRow(relay)
        }, (relay: RelayItem) => `srv-ci-${relay.country}-${relay.city}-${this.srvFilter}`)
        this.srvDivider()
      }

      if (this.srvMatchingRelays().length > 0) {
        this.srvSectionHeader(this.serverMode === 'exit' ? 'Exit relays' : 'Relays')
        ForEach(this.srvMatchingRelays(), (relay: RelayItem) => {
          this.relayRow(relay)
        }, (relay: RelayItem) =>
          `srv-r-${relay.hostname}-${this.serverMode}-${this.selection?.hostname ?? ''}-` +
          `${this.exitSelection?.hostname ?? ''}-${this.srvIsFavourite(relay.hostname) ? '1' : '0'}`)
      }

      if (this.srvMatchingRelays().length === 0 &&
        (this.serverMode !== 'entry' ||
          (this.srvMatchingCountries().length === 0 && this.srvMatchingCities().length === 0))) {
        Text('No relay, city or country matches this search.')
          .fontSize(13)
          .fontColor($r('sys.color.font_tertiary'))
          .width('100%')
          .textAlign(TextAlign.Center)
          .margin({ top: 32 })
      }
    }
    .width('100%')
    .alignItems(HorizontalAlign.Start)
  }

  @Builder
  srvEmptyState() {
    Column({ space: 12 }) {
      SymbolGlyph($r('sys.symbol.bolt_shield'))
        .fontSize(36)
        .fontColor([$r('sys.color.font_tertiary')])
      Text('No relays loaded')
        .fontSize(16)
        .fontWeight(FontWeight.Medium)
        .fontColor($r('sys.color.font_primary'))
      Text('The relay list is empty. Check your connection, then refresh.')
        .fontSize(13)
        .fontColor($r('sys.color.font_secondary'))
        .textAlign(TextAlign.Center)
        .maxLines(2)
      Button('Refresh')
        .type(ButtonType.Capsule)
        .height(40)
        .padding({ left: 24, right: 24 })
        .fontSize(14)
        .fontColor($r('sys.color.font_primary'))
        .backgroundColor($r('sys.color.comp_background_secondary'))
        .enabled(!this.relaysBusy)
        .opacity(this.relaysBusy ? 0.6 : 1)
        .onClick(() => {
          this.refreshRelays();
        })
    }
    .width('100%')
    .layoutWeight(1)
    .padding({ left: 32, right: 32 })
    .justifyContent(FlexAlign.Center)
    .alignItems(HorizontalAlign.Center)
  }

  @Builder
  serversScreen() {
    Column() {
      if (this.serverMode === 'exit') {
        Column({ space: 4 }) {
          Text('Choose the exit relay')
            .fontSize(14)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('sys.color.font_primary'))
          Text('Traffic enters through the selected entry relay and leaves through this one, ' +
            'so neither relay sees both the device and the destination.')
            .fontSize(12)
            .fontColor($r('sys.color.font_secondary'))
            .lineHeight(17)
        }
        .width('100%')
        .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 8, bottom: 2 })
        .alignItems(HorizontalAlign.Start)
      } else if (this.sessionActive() && this.tunnelTarget.length > 0) {
        Column() {
          this.srvConnectedCard()
        }
        .width('100%')
        .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 8 })
      }

      Row() {
        TextInput({
          placeholder: this.serverMode === 'exit' ? 'Search exit relay' : 'Search country, city or relay',
          text: this.search
        })
          .height(40)
          .fontSize(14)
          .backgroundColor($r('sys.color.comp_background_secondary'))
          .borderRadius(20)
          .placeholderColor($r('sys.color.font_tertiary'))
          .caretColor($r('sys.color.brand'))
          .onChange((value: string) => {
            this.search = value;
          })
      }
      .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 8, bottom: 6 })

      Row({ space: 8 }) {
        this.srvFilterChip('All', 'all')
        this.srvFilterChip('DAITA', 'daita')
        this.srvFilterChip('Owned', 'owned')
        this.srvFilterChip('Recent', 'recent')
      }
      .width('100%')
      .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, bottom: 6 })

      if (this.relaysBusy && this.relays.length > 0) {
        Row({ space: 6 }) {
          LoadingProgress()
            .width(12)
            .height(12)
            .color($r('sys.color.font_tertiary'))
          Text('Updating…')
            .fontSize(11)
            .fontColor($r('sys.color.font_tertiary'))
        }
        .padding({ left: 20, bottom: 4 })
      }

      if (this.relays.length === 0 && this.relaysBusy) {
        LoadingProgress()
          .width(32)
          .height(32)
          .color($r('sys.color.brand'))
          .margin({ top: 24 })
      }

      if (this.relaysError.length > 0) {
        Text(this.relaysError)
          .fontSize(13)
          .fontColor($r('sys.color.alert'))
          .padding({ left: 20, right: 20, top: 4 })
      }

      if (this.relays.length === 0) {
        this.srvEmptyState()
      } else {
        Scroll() {
          Column() {
            if (this.srvSearchQuery().length > 0) {
              this.srvSearchResults()
            } else {
              this.automaticRow()
              this.srvDivider()

              if (this.srvFavouriteRelays().length > 0) {
                this.srvSectionHeader('Favourites')
                ForEach(this.srvFavouriteRelays(), (relay: RelayItem) => {
                  this.relayRow(relay)
                }, (relay: RelayItem) =>
                  `srv-fav-${relay.hostname}-${this.srvIsFavourite(relay.hostname) ? '1' : '0'}-${this.selection?.hostname ?? ''}`)
                this.srvDivider()
              }

              if (this.srvRecentRelays().length > 0) {
                this.srvSectionHeader('Recent')
                ForEach(this.srvRecentRelays(), (relay: RelayItem) => {
                  this.relayRow(relay)
                }, (relay: RelayItem) =>
                  `srv-recent-${relay.hostname}-${this.srvIsFavourite(relay.hostname) ? '1' : '0'}-${this.selection?.hostname ?? ''}`)
                this.srvDivider()
              }

              if (this.srvCountries().length > 0) {
                this.srvSectionHeader('Countries')
                ForEach(this.srvCountries(), (country: string) => {
                  Column() {
                    this.countryRow(country)
                    if (this.expandedCountry === country) {
                      ForEach(this.srvCitiesInCountry(country), (city: string) => {
                        Column() {
                          this.srvCityHeader(city, this.srvRelaysInCity(country, city).length)
                          ForEach(this.srvRelaysInCity(country, city), (relay: RelayItem) => {
                            this.srvCityRelayRow(relay)
                          }, (relay: RelayItem) =>
                            `srv-city-${country}-${city}-${relay.hostname}-${this.srvIsFavourite(relay.hostname) ? '1' : '0'}-${this.selection?.hostname ?? ''}`)
                        }
                        .width('100%')
                      }, (city: string) => `srv-citygroup-${country}-${city}-${this.srvFilter}`)
                    }
                  }
                  .width('100%')
                }, (country: string) => `srv-country-${country}-${this.srvFilter}-${this.expandedCountry === country ? 'open' : 'closed'}`)
              } else {
                Text('No relays match this filter.')
                  .fontSize(13)
                  .fontColor($r('sys.color.font_tertiary'))
                  .width('100%')
                  .textAlign(TextAlign.Center)
                  .margin({ top: 24 })
              }
            }
          }
          .width('100%')
          .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, bottom: 16 })
          .alignItems(HorizontalAlign.Start)
        }
        .layoutWeight(1)
        .scrollBar(BarState.Off)
        .align(Alignment.TopStart)
      }
    }
    .width('100%')
    .height('100%')
    .onAppear(() => {
      this.srvLoadFavourites();
    })
  }

  private two(value: number): string {
    return value < 10 ? `0${value}` : `${value}`;
  }

  /** `20261021-232000`, used in file and zip names. */
  private stampFilename(): string {
    const d = new Date();
    return `${d.getFullYear()}${this.two(d.getMonth() + 1)}${this.two(d.getDate())}-` +
      `${this.two(d.getHours())}${this.two(d.getMinutes())}${this.two(d.getSeconds())}`;
  }

  /** `2026-10-21 23:20:00`, used inside the exported text. */
  private stampHuman(): string {
    const d = new Date();
    return `${d.getFullYear()}-${this.two(d.getMonth() + 1)}-${this.two(d.getDate())} ` +
      `${this.two(d.getHours())}:${this.two(d.getMinutes())}:${this.two(d.getSeconds())}`;
  }

  /** Local `20261021-232000` for an entry's ISO start, or `legacy` when it has none. */
  private entryStamp(entry: DiagEntry): string {
    const at: number = Date.parse(entry.startedAt);
    if (isNaN(at)) {
      return 'legacy';
    }
    const d = new Date(at);
    return `${d.getFullYear()}${this.two(d.getMonth() + 1)}${this.two(d.getDate())}-` +
      `${this.two(d.getHours())}${this.two(d.getMinutes())}${this.two(d.getSeconds())}`;
  }

  /** `003-sg-sin-wg-001-20261021-232000.txt`: sortable, and says what is inside. */
  private entryFilename(entry: DiagEntry, index: number): string {
    const safe: string = entry.target.replace(/[^A-Za-z0-9._-]+/g, '-')
      .replace(/^-+/, '').replace(/-+$/, '');
    const host: string = safe.length > 0 ? safe : 'unknown';
    const exit: string = entry.exitHost.length > 0 ?
      `-via-${entry.exitHost.replace(/[^A-Za-z0-9._-]+/g, '-')}` : '';
    const number: string = index < 10 ? `00${index}` : (index < 100 ? `0${index}` : `${index}`);
    return `${number}-${host}${exit}-${this.entryStamp(entry)}.txt`;
  }

  /** Header block every exported entry starts with. */
  private entryHeader(entry: DiagEntry, index: number, total: number, exportedAt: string): string {
    const duration: string = entry.duration.length > 0 ? entry.duration : '-';
    const started: string = entry.startedAt.length > 0 ? entry.startedAt : 'unknown';
    return [
      '=== 燕鸥 (Yàn\'ōu) diagnostics ===',
      `app        燕鸥 (Yàn'ōu) ${APP_VERSION}`,
      `exported   ${exportedAt}`,
      `entry      ${index} of ${total}`,
      `target     ${entry.target}`,
      `started    ${started} (${entry.startedLabel})`,
      `status     ${entry.statusLabel}`,
      `summary    ${entry.summary}`,
      `duration   ${duration}`,
      `attempts   ${entry.attempts}`,
      `multihop   ${entry.multihop ? (entry.exitHost.length > 0 ? `exit ${entry.exitHost}` : 'on') : 'off'}`,
      `lines      ${entry.lineCount}`,
      '---',
      ''
    ].join('\n');
  }

  /** Every distinct relay or country label the exported entries tried. */
  private diagNodes(): string[] {
    const seen: string[] = [];
    for (const entry of this.diagEntries) {
      if (entry.target.length > 0 && !seen.includes(entry.target)) {
        seen.push(entry.target);
      }
    }
    return seen;
  }

  /**
   * Resolves a few names through the default network, which is the tunnel while it is up,
   * and writes the answers to the log. This is the only reliable way to see whether the
   * resolver the tunnel advertises is the one the system actually uses.
   */
  /** Minimal A query for one name, built by hand so the probe needs no resolver API. */
  private dnsQueryBytes(name: string): ArrayBuffer {
    const labels: string[] = name.split('.');
    let size: number = 12;
    for (const label of labels) {
      size += 1 + label.length;
    }
    size += 1 + 4;
    const buffer: ArrayBuffer = new ArrayBuffer(size);
    const view: DataView = new DataView(buffer);
    const bytes: Uint8Array = new Uint8Array(buffer);
    view.setUint16(0, 0x1a2b);
    view.setUint16(2, 0x0100);
    view.setUint16(4, 1);
    let offset: number = 12;
    for (const label of labels) {
      bytes[offset] = label.length;
      offset += 1;
      for (let i = 0; i < label.length; i++) {
        bytes[offset] = label.charCodeAt(i);
        offset += 1;
      }
    }
    bytes[offset] = 0;
    offset += 1;
    view.setUint16(offset, 1);
    view.setUint16(offset + 2, 1);
    return buffer;
  }

  /**
   * Sends one DNS query to a resolver and waits for any answer. The socket is not
   * protected, so its packets follow the default route: into the tunnel when one is up.
   * This separates "the resolver answers and the system ignores it" from "the resolver
   * is unreachable through the tunnel".
   */
  private async probeResolver(address: string): Promise<string> {
    const udp: socket.UDPSocket = socket.constructUDPSocketInstance();
    try {
      await udp.bind({ address: '0.0.0.0', port: 0, family: 1 });
      const reply: Promise<string> = new Promise<string>((resolve: (value: string) => void) => {
        const timer: number = setTimeout(() => {
          resolve('timeout');
        }, 2500);
        udp.on('message', (value: socket.SocketMessageInfo) => {
          clearTimeout(timer);
          resolve(`${value.message.byteLength} B`);
        });
        udp.on('error', (err: BusinessError) => {
          clearTimeout(timer);
          resolve(`error ${err.code ?? -1}`);
        });
      });
      await udp.send({
        data: this.dnsQueryBytes('doubleclick.net'),
        address: { address: address, port: 53, family: 1 }
      });
      return await reply;
    } catch (e) {
      const err = e as BusinessError;
      return `send failed ${err.code ?? -1}`;
    } finally {
      try {
        await udp.close();
      } catch (e) {
        hilog.warn(DOMAIN, TAG, 'probe close failed');
      }
    }
  }

  private async diagDnsCheck(): Promise<void> {
    const hosts: string[] = ['example.com', 'doubleclick.net', 'googlesyndication.com'];
    native.setDiagnostics(this.diagnosticsEnabled);
    native.logLine(`dns check: tunnel resolver ${this.dnsLabel()}`);
    const gatewayProbe: string = await this.probeResolver('10.64.0.1');
    native.logLine(`dns check: 10.64.0.1:53 -> ${gatewayProbe}`);
    const chosen: string = this.dnsLabel().split(',')[0].trim();
    if (chosen.length > 0 && chosen !== '10.64.0.1') {
      const chosenProbe: string = await this.probeResolver(chosen);
      native.logLine(`dns check: ${chosen}:53 -> ${chosenProbe}`);
    }
    for (const host of hosts) {
      try {
        const addresses: connection.NetAddress[] = await connection.getAddressesByName(host);
        const first: string = addresses.length > 0 ? addresses[0].address : 'no address';
        native.logLine(`dns check: ${host} -> ${first}`);
      } catch (e) {
        const err = e as BusinessError;
        native.logLine(`dns check: ${host} -> failed (${err.code ?? -1})`);
      }
    }
    this.readLogs();
  }

  /** Writes a string to a picked document URI. */
  private async saveText(uri: string, text: string): Promise<void> {
    const file = fs.openSync(uri, fs.OpenMode.READ_WRITE | fs.OpenMode.CREATE | fs.OpenMode.TRUNC);
    fs.writeSync(file.fd, text);
    fs.closeSync(file);
  }

  /** Copies a file to a picked document URI in chunks; the picker gives a content URI. */
  private async saveFile(uri: string, path: string): Promise<void> {
    const src = fs.openSync(path, fs.OpenMode.READ_ONLY);
    const dst = fs.openSync(uri, fs.OpenMode.READ_WRITE | fs.OpenMode.CREATE | fs.OpenMode.TRUNC);
    const buffer: ArrayBuffer = new ArrayBuffer(64 * 1024);
    let read: number = fs.readSync(src.fd, buffer);
    while (read > 0) {
      fs.writeSync(dst.fd, buffer, { length: read });
      read = fs.readSync(src.fd, buffer);
    }
    fs.closeSync(src);
    fs.closeSync(dst);
  }

  /** The whole native log as one text file, for when the entries are not enough. */
  private async diagExportRaw(): Promise<void> {
    try {
      const name: string = `yanou-log-${this.stampFilename()}.txt`;
      const options: picker.DocumentSaveOptions = { newFileNames: [name] };
      const documentPicker = new picker.DocumentViewPicker(getContext(this) as common.Context);
      const uris: string[] = await documentPicker.save(options);
      if (uris.length === 0) {
        return;
      }
      await this.saveText(uris[0], this.logText);
    } catch (e) {
      this.logText = `Export failed: ${JSON.stringify(e)}`;
    }
  }

  /**
   * Every parsed entry as its own file, plus a manifest, inside one zip.
   *
   * The files are named so a folder sorts chronologically and each name says which relay
   * and which attempt it is; the manifest lists them and the relays they used, so a report
   * can be read without opening every file.
   */
  private async diagExportZip(): Promise<void> {
    if (this.diagEntries.length === 0) {
      this.logText = 'Nothing to export yet. Connect once with diagnostics on.';
      return;
    }
    const context = getContext(this) as common.Context;
    const exportedAt: string = this.stampHuman();
    const stamp: string = this.stampFilename();
    const dir: string = `${context.cacheDir}/diag-${stamp}`;
    try {
      fs.mkdirSync(dir);
      const paths: string[] = [];
      const files: DiagManifestFile[] = [];
      let index: number = 0;
      for (const entry of this.diagEntries) {
        index += 1;
        const name: string = this.entryFilename(entry, index);
        const path: string = `${dir}/${name}`;
        const text: string = this.entryHeader(entry, index, this.diagEntries.length, exportedAt) +
          entry.body + '\n';
        await this.saveText(path, text);
        paths.push(path);
        files.push({
          name: name,
          target: entry.target,
          exit: entry.exitHost,
          multihop: entry.multihop,
          startedAt: entry.startedAt,
          status: entry.status,
          lines: entry.lineCount
        });
      }
      const manifest: DiagManifest = {
        app: '燕鸥 (Yàn\'ōu)',
        version: APP_VERSION,
        exportedAt: exportedAt,
        entryCount: files.length,
        nodes: this.diagNodes(),
        files: files
      };
      const manifestPath: string = `${dir}/manifest.json`;
      await this.saveText(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
      paths.push(manifestPath);

      const zipName: string = `yanou-diagnostics-${stamp}.zip`;
      const zipPath: string = `${context.cacheDir}/${zipName}`;
      const options: zlib.Options = {
        level: zlib.CompressLevel.COMPRESS_LEVEL_DEFAULT_COMPRESSION,
        memLevel: zlib.MemLevel.MEM_LEVEL_DEFAULT,
        strategy: zlib.CompressStrategy.COMPRESS_STRATEGY_DEFAULT_STRATEGY
      };
      await zlib.compressFiles(paths, zipPath, options);

      const saveOptions: picker.DocumentSaveOptions = { newFileNames: [zipName] };
      const documentPicker = new picker.DocumentViewPicker(context);
      const uris: string[] = await documentPicker.save(saveOptions);
      if (uris.length === 0) {
        return;
      }
      await this.saveFile(uris[0], zipPath);
    } catch (e) {
      this.logText = `Export failed: ${JSON.stringify(e)}`;
    }
  }

  /** Saves the open entry with the same header the zip uses. */
  private async diagExportEntry(): Promise<void> {
    const entry: DiagEntry | null = this.openEntry;
    if (entry === null) {
      return;
    }
    try {
      const index: number = Math.max(0, this.diagEntries.indexOf(entry)) + 1;
      const total: number = this.diagEntries.length > 0 ? this.diagEntries.length : 1;
      const section: string = this.entryHeader(entry, index, total, this.stampHuman()) +
        entry.body + '\n';
      const options: picker.DocumentSaveOptions = {
        newFileNames: [`yanou-${this.entryFilename(entry, index)}`]
      };
      const documentPicker = new picker.DocumentViewPicker(getContext(this) as common.Context);
      const uris: string[] = await documentPicker.save(options);
      if (uris.length === 0) {
        return;
      }
      await this.saveText(uris[0], section);
    } catch (e) {
      // Keep the list and the raw log intact: a failed save must not look like a log read.
      hilog.warn(DOMAIN, TAG, 'entry export failed %{public}s', JSON.stringify(e));
    }
  }

  private statusColor(status: string): ResourceColor {
    if (status === 'connected') {
      return $r('sys.color.confirm');
    }
    if (status === 'failed') {
      return $r('sys.color.alert');
    }
    return $r('sys.color.font_tertiary');
  }

  private copyEntry(): void {
    const body: string = this.openEntry?.body ?? '';
    if (body.length === 0) {
      return;
    }
    const data = pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, body);
    pasteboard.getSystemPasteboard().setData(data).catch((err: BusinessError) => {
      hilog.warn(DOMAIN, TAG, 'clipboard failed %{public}d', err.code);
    });
  }

  /** Filter chips in a fixed order, so they do not jump as counts change. */
  private diagFilters(): string[] {
    return ['all', 'failed', 'connected', 'stopped'];
  }

  /** Entries matching the active chip; `all` keeps the unfiltered list. */
  private diagVisible(): DiagEntry[] {
    if (this.diagFilter === 'all') {
      return this.diagEntries;
    }
    const status: string = this.diagFilter;
    return this.diagEntries.filter((entry: DiagEntry) => entry.status === status);
  }

  /** Chip label with its count, e.g. `Failed 3`; a zero count stays a plain label. */
  private diagChipLabel(filter: string): string {
    if (filter === 'all') {
      return this.diagEntries.length > 0 ? `All ${this.diagEntries.length}` : 'All';
    }
    const counts: DiagStatusCounts = statusCounts(this.diagEntries);
    if (filter === 'failed') {
      return counts.failed > 0 ? `Failed ${counts.failed}` : 'Failed';
    }
    if (filter === 'connected') {
      return counts.connected > 0 ? `Connected ${counts.connected}` : 'Connected';
    }
    return counts.stopped > 0 ? `Stopped ${counts.stopped}` : 'Stopped';
  }

  /** Tails the log while the list is open and diagnostics are on. */
  private diagStartTail(): void {
    this.diagStopTail();
    if (!this.diagnosticsEnabled) {
      return;
    }
    this.diagLive = true;
    this.diagTailTimer = setInterval(() => {
      if (!this.diagnosticsEnabled) {
        this.diagStopTail();
        return;
      }
      this.readLogs();
    }, 3000);
  }

  private diagStopTail(): void {
    if (this.diagTailTimer >= 0) {
      clearInterval(this.diagTailTimer);
      this.diagTailTimer = -1;
    }
    this.diagLive = false;
  }

  @Builder
  diagChip(filter: string) {
    Text(this.diagChipLabel(filter))
      .fontSize(12)
      .fontWeight(this.diagFilter === filter ? FontWeight.Medium : FontWeight.Normal)
      .fontColor(this.diagFilter === filter ?
        $r('sys.color.font_on_primary') : $r('sys.color.font_secondary'))
      .padding({ left: 14, right: 14, top: 7, bottom: 7 })
      .borderRadius(16)
      .backgroundColor(this.diagFilter === filter ?
        $r('sys.color.brand') : $r('sys.color.comp_background_primary'))
      .onClick(() => {
        this.diagFilter = filter;
      })
  }

  @Builder
  diagRow(entry: DiagEntry) {
    Row({ space: 12 }) {
      Circle()
        .width(8)
        .height(8)
        .fill(this.statusColor(entry.status))

      Column({ space: 3 }) {
        Row() {
          Text(entry.target)
            .fontSize(15)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('sys.color.font_primary'))
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
            .layoutWeight(1)
          Text(entry.startedLabel)
            .fontSize(11)
            .fontColor($r('sys.color.font_tertiary'))
            .margin({ left: 8 })
        }
        .width('100%')

        Row() {
          Text(entry.statusLabel)
            .fontSize(12)
            .fontColor(this.statusColor(entry.status))
          if (entry.duration.length > 0) {
            Text(`  ${entry.duration}s`)
              .fontSize(12)
              .fontColor($r('sys.color.font_tertiary'))
          }
          Text(`  ${entry.summary}`)
            .fontSize(12)
            .fontColor($r('sys.color.font_secondary'))
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
            .layoutWeight(1)
        }
        .width('100%')

        if (entry.attempts > 1) {
          Text(`${entry.attempts} relays tried`)
            .fontSize(11)
            .fontColor($r('sys.color.font_tertiary'))
        }
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)

      SymbolGlyph($r('sys.symbol.chevron_right'))
        .fontSize(16)
        .fontColor([$r('sys.color.font_tertiary')])
    }
    .width('100%')
    .padding({ left: 12, right: 12, top: 10, bottom: 10 })
    .borderRadius(12)
    .backgroundColor($r('sys.color.comp_background_primary'))
    .onClick(() => {
      this.openDiagnostics(entry);
    })
  }

  @Builder
  logsScreen() {
    Column({ space: 8 }) {
      Row() {
        Column({ space: 2 }) {
          Text('Enable diagnostics')
            .fontSize(15)
            .fontColor($r('sys.color.font_primary'))
          Text('Off by default. Records one entry per connection attempt.')
            .fontSize(12)
            .fontColor($r('sys.color.font_secondary'))
        }
        .alignItems(HorizontalAlign.Start)
        .layoutWeight(1)

        Toggle({ type: ToggleType.Switch, isOn: this.diagnosticsEnabled })
          .selectedColor($r('sys.color.brand'))
          .onChange((isOn: boolean) => {
            this.diagnosticsEnabled = isOn;
            native.setDiagnostics(isOn);
            VpnSettings.setString(getContext(this) as common.Context, 'diagnostics',
              isOn ? 'true' : 'false');
            if (isOn) {
              this.readLogs();
              this.diagStartTail();
            } else {
              this.diagStopTail();
            }
          })
      }
      .width('calc(100% - 32vp)')
      .padding(12)
      .borderRadius(12)
      .backgroundColor($r('sys.color.comp_background_primary'))
      .margin({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 8 })

      Column({ space: 2 }) {
        Text(`Registered key  ${this.session?.publicKey.substring(0, 16) ?? '-'}`)
          .fontSize(12)
          .fontColor($r('sys.color.font_primary'))
        Text(`Tunnel key     ${this.extensionKey.length > 0 ? this.extensionKey.substring(0, 16) : 'not loaded yet'}`)
          .fontSize(12)
          .fontColor(this.keyMismatch() ? $r('sys.color.alert') : $r('sys.color.font_primary'))
        Text(`Target         ${this.relayLabel()} · phase ${this.phase}`)
          .fontSize(12)
          .fontColor($r('sys.color.font_primary'))
      }
      .width('calc(100% - 32vp)')
      .padding(12)
      .borderRadius(12)
      .backgroundColor($r('sys.color.comp_background_primary'))
      .alignItems(HorizontalAlign.Start)
      .margin({ left: PAGE_GUTTER, right: PAGE_GUTTER })

      Row() {
        Text('Connection entries')
          .fontSize(13)
          .fontWeight(FontWeight.Medium)
          .fontColor($r('sys.color.font_secondary'))
        Blank()
        if (this.diagLive) {
          Circle()
            .width(6)
            .height(6)
            .fill($r('sys.color.confirm'))
            .margin({ right: 4 })
          Text('Live')
            .fontSize(11)
            .fontColor($r('sys.color.confirm'))
            .margin({ right: 8 })
        }
        Text(`${this.diagVisible().length}`)
          .fontSize(12)
          .fontColor($r('sys.color.font_tertiary'))
      }
      .width('calc(100% - 32vp)')
      .margin({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 4 })

      Scroll() {
        Row({ space: 8 }) {
          ForEach(this.diagFilters(), (filter: string) => {
            this.diagChip(filter)
          }, (filter: string) => filter)
        }
        .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER })
      }
      .width('100%')
      .height(36)
      .scrollable(ScrollDirection.Horizontal)
      .scrollBar(BarState.Off)

      Scroll() {
        Column({ space: 8 }) {
          if (this.diagEntries.length === 0) {
            Text(this.diagnosticsEnabled ?
              'Nothing recorded yet. Connect once and come back.' :
              'Diagnostics are off. Turn them on, then connect.')
              .fontSize(13)
              .fontColor($r('sys.color.font_secondary'))
              .padding(16)
          } else if (this.diagVisible().length === 0) {
            Column({ space: 8 }) {
              Text(`No ${this.diagFilter} connections`)
                .fontSize(13)
                .fontColor($r('sys.color.font_secondary'))
              Text('Show all')
                .fontSize(13)
                .fontWeight(FontWeight.Medium)
                .fontColor($r('sys.color.brand'))
                .onClick(() => {
                  this.diagFilter = 'all';
                })
            }
            .alignItems(HorizontalAlign.Start)
            .padding(16)
          }
          ForEach(this.diagVisible(), (entry: DiagEntry) => {
            this.diagRow(entry)
          }, (entry: DiagEntry) => entry.id)
        }
        .width('100%')
        .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, bottom: 12 })
      }
      .layoutWeight(1)
      .width('100%')
      .scrollBar(BarState.Off)
      .align(Alignment.TopStart)

      Row() {
        Button('Check DNS')
          .type(ButtonType.Capsule)
          .width('100%')
          .height(38)
          .fontSize(14)
          .backgroundColor($r('sys.color.comp_background_secondary'))
          .fontColor($r('sys.color.font_secondary'))
          .onClick(() => {
            this.diagDnsCheck();
          })
      }
      .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, bottom: 4 })

      Row({ space: 8 }) {
        Button('Export all (zip)')
          .type(ButtonType.Capsule)
          .layoutWeight(1)
          .height(44)
          .backgroundColor($r('sys.color.brand'))
          .fontColor($r('sys.color.font_on_primary'))
          .onClick(() => {
            this.diagExportZip();
          })
        Button('Raw log')
          .type(ButtonType.Capsule)
          .layoutWeight(1)
          .height(44)
          .backgroundColor($r('sys.color.comp_background_secondary'))
          .fontColor($r('sys.color.font_primary'))
          .onClick(() => {
            this.diagExportRaw();
          })
      }
      .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, bottom: PAGE_GUTTER })
    }
    .width('100%')
    .height('100%')
    .onAppear(() => {
      if (this.diagnosticsEnabled) {
        this.diagStartTail();
      }
    })
    .onDisAppear(() => {
      this.diagStopTail();
    })
  }

  @Builder
  diagDetailScreen() {
    Column({ space: 12 }) {
      Column({ space: 6 }) {
        Row() {
          Text(this.openEntry?.statusLabel ?? 'Entry')
            .fontSize(13)
            .fontWeight(FontWeight.Medium)
            .fontColor(this.statusColor(this.openEntry?.status ?? ''))
          Blank()
          Text(this.openEntry?.startedLabel ?? '')
            .fontSize(12)
            .fontColor($r('sys.color.font_tertiary'))
        }
        .width('100%')

        Text(this.openEntry?.target ?? '')
          .fontSize(17)
          .fontWeight(FontWeight.Medium)
          .fontColor($r('sys.color.font_primary'))
          .width('100%')

        Text(this.openEntry?.summary ?? '')
          .fontSize(13)
          .fontColor($r('sys.color.font_secondary'))
          .width('100%')
      }
      .width('calc(100% - 32vp)')
      .padding(14)
      .borderRadius(12)
      .backgroundColor($r('sys.color.comp_background_primary'))
      .alignItems(HorizontalAlign.Start)
      .margin({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 8 })

      Scroll() {
        Text(this.openEntry?.body ?? '')
          .fontSize(11)
          .lineHeight(17)
          .fontColor($r('sys.color.font_primary'))
          .width('100%')
          .copyOption(CopyOptions.LocalDevice)
          .padding(14)
      }
      .layoutWeight(1)
      .width('calc(100% - 32vp)')
      .margin({ left: PAGE_GUTTER, right: PAGE_GUTTER })
      .borderRadius(12)
      .backgroundColor($r('sys.color.comp_background_primary'))
      .align(Alignment.TopStart)

      Row({ space: 8 }) {
        Button('Copy')
          .type(ButtonType.Capsule)
          .layoutWeight(1)
          .height(44)
          .backgroundColor($r('sys.color.comp_background_secondary'))
          .fontColor($r('sys.color.font_primary'))
          .onClick(() => {
            this.copyEntry();
          })
        Button('Export')
          .type(ButtonType.Capsule)
          .layoutWeight(1)
          .height(44)
          .backgroundColor($r('sys.color.comp_background_secondary'))
          .fontColor($r('sys.color.font_primary'))
          .onClick(() => {
            this.diagExportEntry();
          })
      }
      .width('calc(100% - 32vp)')
      .margin({ left: PAGE_GUTTER, right: PAGE_GUTTER, bottom: PAGE_GUTTER })
    }
    .width('100%')
    .height('100%')
  }

  // ---------------------------------------------------------------- account

  /** Whole days until the account expires; 9999 when the date is unknown, negative once past. */
  private acctDaysLeft(): number {
    // `session.expiry` is the access-token expiry (minutes to days); the account expiry
    // only comes from /accounts/me, so nothing is shown until that has been fetched.
    const at: number = Date.parse(this.accountExpiryIso);
    if (isNaN(at)) {
      return 9999;
    }
    return Math.floor((at - Date.now()) / (24 * 60 * 60 * 1000));
  }

  private acctDaysLabel(): string {
    const days: number = this.acctDaysLeft();
    if (days === 9999) {
      return '';
    }
    if (days < 0) {
      return 'Expired';
    }
    if (days === 0) {
      return 'Expires today';
    }
    return days === 1 ? '1 day left' : `${days} days left`;
  }

  private acctDaysColor(): ResourceColor {
    const days: number = this.acctDaysLeft();
    if (days === 9999) {
      return $r('sys.color.font_secondary');
    }
    if (days < 0 || days <= 7) {
      return $r('sys.color.alert');
    }
    if (days <= 14) {
      return $r('sys.color.font_secondary');
    }
    return $r('sys.color.confirm');
  }

  /** Warn on the last week, and keep warning once the account has lapsed. */
  private acctShouldWarn(): boolean {
    const days: number = this.acctDaysLeft();
    return days !== 9999 && days <= 7;
  }

  private acctBannerText(): string {
    const days: number = this.acctDaysLeft();
    if (days < 0) {
      return 'Your account has expired';
    }
    if (days === 0) {
      return 'Your account expires today';
    }
    return `Your account expires in ${days} ${days === 1 ? 'day' : 'days'}`;
  }

  /** Confirmation for icon-only copy actions; without it the tap feels like nothing. */
  private acctToast(message: string): void {
    promptAction.showToast({ message: message, duration: 1600 });
  }

  /** Mullvad device management folded into Account; the `devices` destination stays for deep links. */
  @Builder
  accountScreen() {
    Scroll() {
      Column() {
        if (this.acctShouldWarn()) {
          Column({ space: 10 }) {
            Row({ space: 8 }) {
              SymbolGlyph($r('sys.symbol.exclamationmark_triangle'))
                .fontSize(18)
                .fontColor([$r('sys.color.alert')])
              Text(this.acctBannerText())
                .fontSize(14)
                .fontWeight(FontWeight.Medium)
                .fontColor($r('sys.color.font_primary'))
                .layoutWeight(1)
            }
            .width('100%')

            Button('Copy account number')
              .type(ButtonType.Capsule)
              .height(38)
              .padding({ left: 16, right: 16 })
              .fontSize(14)
              .backgroundColor($r('sys.color.comp_background_secondary'))
              .fontColor($r('sys.color.brand'))
              .onClick(() => {
                this.copyAccount();
              })
          }
          .width('calc(100% - 32vp)')
          .padding(16)
          .alignItems(HorizontalAlign.Start)
          .margin({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 12 })
          .borderRadius(CARD_RADIUS)
          .border({ width: 1, color: $r('sys.color.alert') })
          .backgroundColor($r('sys.color.comp_background_primary'))
        }

        Column() {
          Row() {
            Text('Account number')
              .fontSize(15)
              .fontColor($r('sys.color.font_primary'))
            Blank()
            Text(this.revealAccount ? (this.session?.account ?? '') : maskAccount(this.session?.account ?? ''))
              .fontSize(15)
              .fontColor($r('sys.color.font_secondary'))
            Row() {
              SymbolGlyph(this.revealAccount ? $r('sys.symbol.eye_slash') : $r('sys.symbol.eye'))
                .fontSize(18)
                .fontColor([$r('sys.color.font_secondary')])
            }
            .width(44)
            .height(44)
            .justifyContent(FlexAlign.Center)
            .onClick(() => {
              this.revealAccount = !this.revealAccount;
            })

            Row() {
              SymbolGlyph($r('sys.symbol.doc_text_on_doc_text'))
                .fontSize(18)
                .fontColor([$r('sys.color.font_secondary')])
            }
            .width(44)
            .height(44)
            .justifyContent(FlexAlign.Center)
            .onClick(() => {
              this.copyAccount();
            })
          }
          .width('100%')
          .height(52)

          Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

          Row() {
            Text('Expires')
              .fontSize(15)
              .fontColor($r('sys.color.font_primary'))
            Blank()
            Column({ space: 2 }) {
              Text(this.accountExpiry.length > 0 ? this.accountExpiry : '…')
                .fontSize(15)
                .fontColor($r('sys.color.font_secondary'))
              if (this.acctDaysLabel().length > 0) {
                Text(this.acctDaysLabel())
                  .fontSize(12)
                  .fontColor(this.acctDaysColor())
              }
            }
            .alignItems(HorizontalAlign.End)
          }
          .width('100%')
          .height(52)

          Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

          Row() {
            Text('This device')
              .fontSize(15)
              .fontColor($r('sys.color.font_primary'))
            Blank()
            Text(this.session?.deviceName ?? '')
              .fontSize(15)
              .fontColor($r('sys.color.font_secondary'))
          }
          .width('100%')
          .height(44)
        }
        .width('calc(100% - 32vp)')
        .padding({ left: 16, right: 16 })
        .margin({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 12 })
        .borderRadius(CARD_RADIUS)
        .backgroundColor($r('sys.color.comp_background_primary'))

        Column() {
          Row() {
            Text('Devices')
              .fontSize(15)
              .fontWeight(FontWeight.Medium)
              .fontColor($r('sys.color.font_primary'))
            Blank()
            Text(this.acctEditDevices ? 'Done' : 'Manage')
              .fontSize(14)
              .fontWeight(FontWeight.Medium)
              .fontColor($r('sys.color.brand'))
              .onClick(() => {
                this.acctEditDevices = !this.acctEditDevices;
              })
          }
          .width('100%')
          .height(48)

          Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

          if (this.devicesError.length > 0) {
            Text(this.devicesError)
              .fontSize(12)
              .fontColor($r('sys.color.alert'))
              .width('100%')
              .padding({ top: 8, bottom: 8 })
          }

          if (this.devices.length === 0 && !this.devicesBusy) {
            Text('No devices on this account yet.')
              .fontSize(12)
              .fontColor($r('sys.color.font_tertiary'))
              .width('100%')
              .padding({ top: 12, bottom: 12 })
          }

          ForEach(this.devices, (device: DeviceResponse, index: number) => {
            Column() {
              if (index > 0) {
                Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))
              }
              Row() {
                Column({ space: 2 }) {
                  Text(device.name)
                    .fontSize(14)
                    .fontWeight(FontWeight.Medium)
                    .fontColor($r('sys.color.font_primary'))
                  Text(`${device.ipv4_address} · added ${formatDate(device.created)}`)
                    .fontSize(12)
                    .fontColor($r('sys.color.font_secondary'))
                }
                .alignItems(HorizontalAlign.Start)
                .layoutWeight(1)

                if (this.removingId === device.id) {
                  LoadingProgress()
                    .width(24)
                    .height(24)
                    .color($r('sys.color.brand'))
                } else if (this.acctEditDevices) {
                  Button() {
                    Text('Remove')
                      .fontSize(13)
                      .fontColor($r('sys.color.alert'))
                  }
                  .type(ButtonType.Capsule)
                  .height(32)
                  .padding({ left: 14, right: 14 })
                  .backgroundColor($r('sys.color.comp_background_secondary'))
                  .onClick(() => {
                    this.confirmRemove(device);
                  })
                } else if (device.id === this.session?.deviceId) {
                  Text('This tablet')
                    .fontSize(12)
                    .fontColor($r('sys.color.brand'))
                }
              }
              .width('100%')
              .padding({ top: 10, bottom: 10 })
            }
            .width('100%')
          }, (device: DeviceResponse) => device.id)
        }
        .width('calc(100% - 32vp)')
        .padding({ left: 16, right: 16, top: 4, bottom: 4 })
        .margin({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 12 })
        .borderRadius(CARD_RADIUS)
        .backgroundColor($r('sys.color.comp_background_primary'))

        Row() {
          Button('Sign out')
            .type(ButtonType.Capsule)
            .width('100%')
            .height(48)
            .backgroundColor($r('sys.color.comp_background_primary'))
            .fontColor($r('sys.color.alert'))
            .onClick(() => {
              this.signOut();
              this.pageStack.clear();
            })
        }
        .padding({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 16, bottom: 24 })
      }
      .width('100%')
    }
    .width('100%')
    .height('100%')
    .align(Alignment.TopStart)
    .scrollBar(BarState.Off)
  }

  // ---------------------------------------------------------------- settings

  private setProtocolModes(): string[] {
    return ['auto', 'direct', 'obfuscated'];
  }

  private setProtocolName(mode: string): string {
    if (mode === 'direct') {
      return 'WireGuard only';
    }
    if (mode === 'obfuscated') {
      return 'Obfuscated only';
    }
    return 'Automatic';
  }

  private setProtocolHint(): string {
    if (this.protocolMode === 'direct') {
      return 'Plain WireGuard only: fastest, but blocked on networks that filter VPN traffic.';
    }
    if (this.protocolMode === 'obfuscated') {
      return 'Only the obfuscated transports: LWO, Shadowsocks, udp2tcp and QUIC. Slower, but works where WireGuard is blocked.';
    }
    return 'Tries plain WireGuard first, then LWO, Shadowsocks, udp2tcp and QUIC when a network blocks it.';
  }

  /** A hand-edited or stale stored value must not leave the segmented control empty. */
  private setNormalizeMode(value: string): string {
    if (value === 'direct' || value === 'obfuscated') {
      return value;
    }
    return 'auto';
  }

  private async setLoadProtocolMode(): Promise<void> {
    const stored: string = await VpnSettings.getString(getContext(this) as common.Context,
      'protocolMode', 'auto');
    this.protocolMode = this.setNormalizeMode(stored);
  }

  private setProtocolMode(mode: string): void {
    this.protocolMode = mode;
    VpnSettings.setString(getContext(this) as common.Context, 'protocolMode', mode)
      .catch((err: BusinessError) => {
        hilog.warn(DOMAIN, TAG, 'protocol mode save failed %{public}d', err.code);
      });
  }

  private setDnsModes(): DnsMode[] {
    return ['auto', 'custom'];
  }

  private setDnsName(mode: DnsMode): string {
    return mode === 'custom' ? 'Custom' : 'Automatic';
  }

  private setDnsHint(): string {
    if (this.prefs.dnsMode !== 'custom') {
      return 'Queries go to the tunnel resolver. Content blocking changes its address.';
    }
    if (this.prefs.customDns.length === 0) {
      return 'Add at least one resolver; until then the tunnel resolver is used.';
    }
    return 'Queries go to these resolvers instead of the tunnel resolver.';
  }

  private setDnsMode(mode: DnsMode): void {
    if (this.prefs.dnsMode === mode) {
      return;
    }
    this.prefs.dnsMode = mode;
    this.dnsError = '';
    this.setPrefText('dnsMode', mode);
  }

  /** Adds the address in the field; empty, malformed and duplicate entries stay out. */
  private setAddDns(): void {
    const address: string = normalizeDnsAddress(this.dnsInput);
    if (address.length === 0) {
      this.dnsError = 'Enter an address.';
      return;
    }
    if (!isValidDnsAddress(address)) {
      this.dnsError = 'Not an IPv4 or IPv6 address.';
      return;
    }
    if (this.prefs.customDns.indexOf(address) >= 0) {
      this.dnsError = 'Already in the list.';
      return;
    }
    // A new array, not a push: `prefs` is @State and only a first-level assignment
    // re-renders the list.
    this.prefs.customDns = this.prefs.customDns.concat([address]);
    this.dnsInput = '';
    this.dnsError = '';
    this.setPrefText('customDns', JSON.stringify(this.prefs.customDns));
  }

  private setRemoveDns(address: string): void {
    this.prefs.customDns = this.prefs.customDns.filter((item: string) => item !== address);
    this.dnsError = '';
    this.setPrefText('customDns', JSON.stringify(this.prefs.customDns));
  }

  private setBlockHint(): string {
    return this.prefs.dnsMode === 'auto' ?
      'The categories are combined into the tunnel resolver address.' :
      'Only applies to automatic DNS; switch the mode above to use these.';
  }

  /** Reads one content-blocking switch by preference key. */
  private setBlockValue(key: string): boolean {
    if (key === 'blockAds') {
      return this.prefs.blockAds;
    }
    if (key === 'blockTrackers') {
      return this.prefs.blockTrackers;
    }
    if (key === 'blockMalware') {
      return this.prefs.blockMalware;
    }
    if (key === 'blockAdult') {
      return this.prefs.blockAdult;
    }
    if (key === 'blockGambling') {
      return this.prefs.blockGambling;
    }
    return this.prefs.blockSocial;
  }

  /** One content-blocking switch; the six booleans share the preferences store. */
  private setBlock(key: string, value: boolean): void {
    if (key === 'blockAds') {
      this.prefs.blockAds = value;
    } else if (key === 'blockTrackers') {
      this.prefs.blockTrackers = value;
    } else if (key === 'blockMalware') {
      this.prefs.blockMalware = value;
    } else if (key === 'blockAdult') {
      this.prefs.blockAdult = value;
    } else if (key === 'blockGambling') {
      this.prefs.blockGambling = value;
    } else if (key === 'blockSocial') {
      this.prefs.blockSocial = value;
    }
    this.setPref(key, value);
  }

  @Builder
  blockRow(label: string, key: string) {
    Row() {
      Text(label)
        .fontSize(15)
        .fontColor($r('sys.color.font_primary'))
      Blank()
      Toggle({ type: ToggleType.Switch, isOn: this.setBlockValue(key) })
        .selectedColor($r('sys.color.brand'))
        .enabled(this.prefs.dnsMode === 'auto')
        .onChange((value: boolean) => {
          this.setBlock(key, value);
        })
    }
    .width('100%')
    .height(44)
    .opacity(this.prefs.dnsMode === 'auto' ? 1 : 0.5)
  }

  /** Copies the last diagnostics text the tunnel wrote; Settings only reads it. */
  private setCopyDiagnostics(): void {
    const data = pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, this.logText);
    pasteboard.getSystemPasteboard().setData(data).catch((err: BusinessError) => {
      hilog.warn(DOMAIN, TAG, 'clipboard failed %{public}d', err.code);
    });
  }

  @Builder
  dnsScreen() {
    Scroll() {
      Column({ space: 12 }) {
        Column({ space: 8 }) {
        Column({ space: 8 }) {
          Text('DNS')
            .fontSize(15)
            .fontColor($r('sys.color.font_primary'))

          Row({ space: 4 }) {
            ForEach(this.setDnsModes(), (mode: DnsMode) => {
              Button(this.setDnsName(mode))
                .type(ButtonType.Normal)
                .layoutWeight(1)
                .height(34)
                .borderRadius(8)
                .fontSize(11)
                .padding({ left: 0, right: 0 })
                .backgroundColor(this.prefs.dnsMode === mode ?
                  $r('sys.color.brand') : Color.Transparent)
                .fontColor(this.prefs.dnsMode === mode ?
                  Color.White : $r('sys.color.font_secondary'))
                .onClick(() => {
                  this.setDnsMode(mode);
                })
            }, (mode: DnsMode) => mode)
          }
          .width('100%')
          .padding(3)
          .borderRadius(10)
          .backgroundColor($r('sys.color.comp_background_secondary'))

          Text(this.setDnsHint())
            .fontSize(12)
            .fontColor($r('sys.color.font_secondary'))
            .width('100%')

          if (this.prefs.dnsMode === 'custom') {
            ForEach(this.prefs.customDns, (address: string) => {
              Row() {
                Text(address)
                  .fontSize(15)
                  .fontColor($r('sys.color.font_primary'))
                  .layoutWeight(1)
                Button('Remove')
                  .type(ButtonType.Capsule)
                  .height(28)
                  .fontSize(12)
                  .padding({ left: 12, right: 12 })
                  .backgroundColor($r('sys.color.comp_background_secondary'))
                  .fontColor($r('sys.color.alert'))
                  .onClick(() => {
                    this.setRemoveDns(address);
                  })
              }
              .width('100%')
              .height(40)
            }, (address: string) => address)

            Row({ space: 8 }) {
              TextInput({ placeholder: 'IPv4 or IPv6 address', text: this.dnsInput })
                .layoutWeight(1)
                .height(38)
                .fontSize(14)
                .backgroundColor($r('sys.color.comp_background_secondary'))
                .borderRadius(8)
                .placeholderColor($r('sys.color.font_tertiary'))
                .caretColor($r('sys.color.brand'))
                .onChange((value: string) => {
                  this.dnsInput = value;
                  this.dnsError = '';
                })
              Button('Add')
                .type(ButtonType.Capsule)
                .height(38)
                .fontSize(14)
                .padding({ left: 18, right: 18 })
                .backgroundColor($r('sys.color.brand'))
                .fontColor(Color.White)
                .onClick(() => {
                  this.setAddDns();
                })
            }
            .width('100%')

            if (this.dnsError.length > 0) {
              Text(this.dnsError)
                .fontSize(12)
                .fontColor($r('sys.color.alert'))
                .width('100%')
            }
          }
        }
        .width('100%')
        .padding({ top: 12, bottom: 12 })
        .alignItems(HorizontalAlign.Start)

        Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

        Column({ space: 4 }) {
          Text('Content blocking')
            .fontSize(15)
            .fontColor($r('sys.color.font_primary'))
          Text(this.setBlockHint())
            .fontSize(12)
            .fontColor($r('sys.color.font_secondary'))
            .width('100%')
            .margin({ bottom: 4 })

          this.blockRow('Ads', 'blockAds')
          Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))
          this.blockRow('Trackers', 'blockTrackers')
          Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))
          this.blockRow('Malware', 'blockMalware')
          Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))
          this.blockRow('Adult content', 'blockAdult')
          Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))
          this.blockRow('Gambling', 'blockGambling')
          Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))
          this.blockRow('Social media', 'blockSocial')
        }
        .width('100%')
        .padding({ top: 12, bottom: 6 })
        .alignItems(HorizontalAlign.Start)
        }
        .width('100%')
        .padding({ left: 16, right: 16, top: 12, bottom: 12 })
        .borderRadius(CARD_RADIUS)
        .backgroundColor($r('sys.color.comp_background_primary'))
        .alignItems(HorizontalAlign.Start)
      }
      .width('calc(100% - 32vp)')
      .margin({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 12 })
    }
    .width('100%')
    .height('100%')
    .scrollBar(BarState.Off)
    .align(Alignment.TopStart)
  }

  @Builder
  settingsScreen() {
    Scroll() {
      Column() {
        if (this.settingsReady) {
          Column() {
            Column({ space: 8 }) {
              Text('Protocol preference')
                .fontSize(15)
                .fontColor($r('sys.color.font_primary'))

              Row({ space: 4 }) {
                ForEach(this.setProtocolModes(), (mode: string) => {
                  Button(this.setProtocolName(mode))
                    .type(ButtonType.Normal)
                    .layoutWeight(1)
                    .height(34)
                    .borderRadius(8)
                    .fontSize(11)
                    .padding({ left: 0, right: 0 })
                    .backgroundColor(this.protocolMode === mode ?
                      $r('sys.color.brand') : Color.Transparent)
                    .fontColor(this.protocolMode === mode ?
                      Color.White : $r('sys.color.font_secondary'))
                    .onClick(() => {
                      this.setProtocolMode(mode);
                    })
                }, (mode: string) => mode)
              }
              .width('100%')
              .padding(3)
              .borderRadius(10)
              .backgroundColor($r('sys.color.comp_background_secondary'))

              Text(this.setProtocolHint())
                .fontSize(12)
                .fontColor($r('sys.color.font_secondary'))
                .width('100%')
            }
            .width('100%')
            .padding({ top: 12, bottom: 12 })
            .alignItems(HorizontalAlign.Start)

            Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

            Row() {
              Column({ space: 2 }) {
                Text('Kill switch')
                  .fontSize(15)
                  .fontColor($r('sys.color.font_primary'))
                Text('Blocks all traffic whenever the tunnel is down.')
                  .fontSize(12)
                  .fontColor($r('sys.color.font_secondary'))
                if (!this.prefs.killSwitch) {
                  Text('Your traffic is unprotected when the VPN drops.')
                    .fontSize(12)
                    .fontColor($r('sys.color.font_tertiary'))
                }
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1)

              Toggle({ type: ToggleType.Switch, isOn: this.prefs.killSwitch })
                .selectedColor($r('sys.color.brand'))
                .onChange((isOn: boolean) => {
                  this.prefs.killSwitch = isOn;
                  this.setPref('killSwitch', isOn);
                })
            }
            .width('100%')
            .padding({ top: 10, bottom: 10 })

            Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

            Column({ space: 8 }) {
              Column({ space: 2 }) {
                Text('Device IP version')
                  .fontSize(15)
                  .fontColor($r('sys.color.font_primary'))
                Text('The other family is dropped inside the tunnel and blocked on the carrier')
                  .fontSize(12)
                  .fontColor($r('sys.color.font_secondary'))
              }
              .alignItems(HorizontalAlign.Start)
              .width('100%')

              Row({ space: 8 }) {
                this.ipOption('IPv4 only', 'ipv4')
                this.ipOption('IPv6 only', 'ipv6')
                this.ipOption('Both', 'auto')
              }
              .width('100%')
            }
            .width('100%')
            .padding({ top: 12, bottom: 12 })

            Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

            Row() {
              Column({ space: 2 }) {
                Text('DNS')
                  .fontSize(15)
                  .fontColor($r('sys.color.font_primary'))
                Text(this.dnsSummary())
                  .fontSize(12)
                  .fontColor($r('sys.color.font_secondary'))
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1)

              SymbolGlyph($r('sys.symbol.chevron_right'))
                .fontSize(16)
                .fontColor([$r('sys.color.font_tertiary')])
            }
            .width('100%')
            .height(60)
            .onClick(() => {
              this.pageStack.pushPath({ name: 'dns' });
            })

            Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

            Row() {
              Column({ space: 2 }) {
                Text('Direct connection')
                  .fontSize(15)
                  .fontColor($r('sys.color.font_primary'))
                Text('Off keeps api.mullvad.net out of DNS and TLS SNI; everything goes through the CDN tunnel')
                  .fontSize(12)
                  .fontColor($r('sys.color.font_secondary'))
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1)

              Toggle({ type: ToggleType.Switch, isOn: this.prefs.directAllowed })
                .selectedColor($r('sys.color.brand'))
                .onChange((isOn: boolean) => {
                  this.prefs.directAllowed = isOn;
                  native.setDirectAllowed(isOn);
                  this.setPref('directAllowed', isOn);
                })
            }
            .width('100%')
            .height(60)

            Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

            Row() {
              Column({ space: 2 }) {
                Text('Relay socket')
                  .fontSize(15)
                  .fontColor($r('sys.color.font_primary'))
                Text(this.protectedFd >= 0 ? `protected · fd ${this.protectedFd}` :
                  'bypasses the tunnel through the app exclusion')
                  .fontSize(12)
                  .fontColor($r('sys.color.brand'))
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1)
            }
            .width('100%')
            .height(60)

            Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

            Row() {
              Column({ space: 2 }) {
                Text('Diagnostics')
                  .fontSize(15)
                  .fontColor($r('sys.color.font_primary'))
                Text('Tunnel log, device keys, what the client is pointed at')
                  .fontSize(12)
                  .fontColor($r('sys.color.font_secondary'))
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1)

              SymbolGlyph($r('sys.symbol.chevron_right'))
                .fontSize(16)
                .fontColor([$r('sys.color.font_tertiary')])
            }
            .width('100%')
            .height(60)
            .onClick(() => {
              this.readLogs();
              this.diagStartTail();
              this.pageStack.pushPath({ name: 'logs' });
            })

            Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

            Row() {
              Column({ space: 2 }) {
                Text('About')
                  .fontSize(15)
                  .fontColor($r('sys.color.font_primary'))
                Text('Client, not a service · not endorsed by Mullvad')
                  .fontSize(12)
                  .fontColor($r('sys.color.font_secondary'))
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1)

              SymbolGlyph($r('sys.symbol.chevron_right'))
                .fontSize(16)
                .fontColor([$r('sys.color.font_tertiary')])
            }
            .width('100%')
            .height(60)
            .onClick(() => {
              this.pageStack.pushPath({ name: 'about' });
            })

            Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

            Row() {
              Column({ space: 2 }) {
                Text('DAITA')
                  .fontSize(15)
                  .fontColor($r('sys.color.font_primary'))
                Text('Only use relays that defend against AI-guided traffic analysis')
                  .fontSize(12)
                  .fontColor($r('sys.color.font_secondary'))
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1)

              Toggle({ type: ToggleType.Switch, isOn: this.prefs.daita })
                .selectedColor($r('sys.color.brand'))
                .onChange((isOn: boolean) => {
                  this.prefs.daita = isOn;
                  this.setPref('daita', isOn);
                  // The list is filtered by this, so drop a selection that no longer fits.
                  if (isOn && this.selection !== null) {
                    this.relays = this.relays.filter((relay: RelayItem) => relay.daita);
                  }
                })
            }
            .width('100%')
            .height(60)

            Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

            Row() {
              Column({ space: 2 }) {
                Text('Multihop')
                  .fontSize(15)
                  .fontColor($r('sys.color.font_primary'))
                Text(!this.prefs.multihop ?
                  'Send traffic through an entry relay, then a separate exit relay' :
                  (this.exitSelection === null ? 'On · choose an exit relay' :
                    `Exit ${this.exitLabel()}`))
                  .fontSize(12)
                  .fontColor($r('sys.color.font_secondary'))
                  .maxLines(2)
              }
              .alignItems(HorizontalAlign.Start)
              .layoutWeight(1)

              Toggle({ type: ToggleType.Switch, isOn: this.prefs.multihop })
                .selectedColor($r('sys.color.brand'))
                .onChange((isOn: boolean) => {
                  this.prefs.multihop = isOn;
                  this.setPref('multihop', isOn);
                })
            }
            .width('100%')
            .padding({ top: 10, bottom: 10 })

            if (this.prefs.multihop) {
              Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

              Row() {
                Column({ space: 2 }) {
                  Text('Exit relay')
                    .fontSize(15)
                    .fontColor($r('sys.color.font_primary'))
                  Text(this.exitSelection === null ?
                    'Not selected · traffic still leaves through the entry relay' :
                    `${this.exitSelection.hostname} · ${this.exitLabel()}`)
                    .fontSize(12)
                    .fontColor(this.exitSelection === null ?
                      $r('sys.color.font_tertiary') : $r('sys.color.font_secondary'))
                    .maxLines(1)
                    .textOverflow({ overflow: TextOverflow.Ellipsis })
                }
                .alignItems(HorizontalAlign.Start)
                .layoutWeight(1)

                SymbolGlyph($r('sys.symbol.chevron_right'))
                  .fontSize(16)
                  .fontColor([$r('sys.color.font_tertiary')])
              }
              .width('100%')
              .height(60)
              .onClick(() => {
                this.openServers('exit');
              })
            }
          }
          .width('calc(100% - 32vp)')
          .padding({ left: 16, right: 16 })
          .borderRadius(CARD_RADIUS)
          .backgroundColor($r('sys.color.comp_background_primary'))
          .margin({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 12 })
        }

        Column() {
          Row() {
            Text('燕鸥')
              .fontSize(15)
              .fontColor($r('sys.color.font_primary'))
            Blank()
            Text('0.1.0')
              .fontSize(14)
              .fontColor($r('sys.color.font_secondary'))
          }
          .width('100%')
          .height(44)

          Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

          Row() {
            Text('License')
              .fontSize(15)
              .fontColor($r('sys.color.font_primary'))
            Blank()
            Text('GPL-3.0-or-later')
              .fontSize(14)
              .fontColor($r('sys.color.font_secondary'))
          }
          .width('100%')
          .height(44)

          Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

          Text("Based on Mullvad's client (mullvadvpn-app)")
            .fontSize(12)
            .fontColor($r('sys.color.font_secondary'))
            .width('100%')
            .padding({ top: 10, bottom: 10 })

          Divider().strokeWidth(0.5).color($r('sys.color.comp_divider'))

          Button('Copy diagnostics')
            .type(ButtonType.Capsule)
            .width('100%')
            .height(38)
            .fontSize(14)
            .backgroundColor($r('sys.color.comp_background_secondary'))
            .fontColor($r('sys.color.brand'))
            .margin({ top: 12, bottom: 12 })
            .onClick(() => {
              this.setCopyDiagnostics();
            })
        }
        .width('calc(100% - 32vp)')
        .padding({ left: 16, right: 16 })
        .borderRadius(CARD_RADIUS)
        .backgroundColor($r('sys.color.comp_background_primary'))
        .margin({ left: PAGE_GUTTER, right: PAGE_GUTTER, top: 12 })
      }
      .width('100%')
      .padding({ bottom: 24 })
    }
    .width('100%')
    .height('100%')
    .align(Alignment.TopStart)
    .scrollBar(BarState.Off)
    .onAppear(() => {
      this.setLoadProtocolMode();
    })
  }

  // ---------------------------------------------------------------- host

  @Builder
  pageMap(name: string) {
    NavDestination() {
      Row() {
        Column() {
          if (name === 'devices') {
            this.devicesScreen()
          } else if (name === 'servers') {
            this.serversScreen()
          } else if (name === 'logs') {
            this.logsScreen()
          } else if (name === 'entry') {
            this.diagDetailScreen()
          } else if (name === 'account') {
            this.accountScreen()
          } else if (name === 'settings') {
            this.settingsScreen()
          } else if (name === 'dns') {
            this.dnsScreen()
          } else if (name === 'about') {
            this.aboutScreen()
          }
        }
        .width('100%')
        .height('100%')
        .constraintSize({ maxWidth: CONTENT_MAX_WIDTH })
      }
      .width('100%')
      .height('100%')
      .justifyContent(FlexAlign.Center)
      .alignItems(VerticalAlign.Top)
    }
    .title(name === 'devices' ? 'Devices' :
      (name === 'servers' ? (this.serverMode === 'exit' ? 'Exit relay' : 'Servers') :
        (name === 'logs' ? 'Diagnostics' :
          (name === 'entry' ? 'Connection' :
            (name === 'account' ? 'Account' :
              (name === 'about' ? 'About' : (name === 'dns' ? 'DNS' : 'VPN settings')))))))
    .backgroundColor($r('sys.color.background_secondary'))
  }

  build() {
    Navigation(this.pageStack) {
      Row() {
        Column() {
          if (this.session === null) {
            this.loginScreen()
          } else {
            this.mainScreen()
          }
        }
        .width('100%')
        .height('100%')
        .constraintSize({ maxWidth: CONTENT_MAX_WIDTH })
      }
      .width('100%')
      .height('100%')
      .justifyContent(FlexAlign.Center)
      .alignItems(VerticalAlign.Top)
    }
    .mode(NavigationMode.Stack)
    .hideTitleBar(true)
    .navDestination(this.pageMap)
    .width('100%')
    .height('100%')
    .backgroundColor($r('sys.color.background_secondary'))
    .expandSafeArea([SafeAreaType.SYSTEM], [SafeAreaEdge.TOP, SafeAreaEdge.BOTTOM])
  }
}
