/**
 * Type surface of entry/src/main/cpp/muharmony_napi.c.
 *
 * Numbers in, numbers out: the native core owns the tun fd and reports counters as
 * JSON so the ArkTS side never parses a binary layout. A negative return value is an
 * error code from the Rust side (-1 bad argument, -2 tun create failed, -3 non-blocking
 * setup failed).
 */

/** Stores the extension's files directory for the native log. Returns 0. */
export const init: (filesDir: string) => number;

/**
 * The device's WireGuard identity: loads `wireguard.key` from the files directory or creates
 * it, and answers `{"publicKey":"<base64>"}`. The private key stays in the native process.
 */
export const wgKey: () => string;

/**
 * Reads the stored key without creating one: `{"publicKey":"<base64>"}`, or an empty
 * `publicKey` when none exists. The tunnel uses this so it can never register-less key.
 */
export const deviceKey: () => string;

/**
 * Deletes the stored key and creates a new one, answering `{"publicKey":"<base64>"}`.
 * Called on every sign-in: Mullvad does not accept a reused device key.
 */
export const rotateKey: () => string;

/** Deletes the stored key. Called on sign-out. Returns 0, or negative on error. */
export const clearKey: () => number;

/** Creates the UDP socket that will be exempted from the tunnel. Returns its fd, or negative on error. */
export const openUdp: (host: string, port: number) => number;

/** Wraps the system-supplied tun fd and starts the reader thread. Returns 0 on success. */
export const attachTun: (fd: number, mtu: number) => number;

/** `{"packets":n,"bytes":n,"protectedFd":n,"uptimeMs":n,"lastDst":"a.b.c.d"}`. */
export const stats: () => string;

/** Stops the reader thread and drops the relay socket. */
export const stop: () => void;

/**
 * Signs in against the Mullvad API from the native side, because the API is unreachable
 * on a censored network without domain fronting. Answers JSON:
 * `{"ok":true,"session":{...}}` or `{"ok":false,"code":"...","error":"...","token"?:...}`.
 * The token is included on failure so the device-management screen can still list devices.
 * Resolves on a worker thread, so the UI does not block on the fronted handshake.
 */
/**
 * Whether the unfronted path may be attempted. Off by default: a direct attempt sends
 * `api.mullvad.net` as TLS SNI in clear text; the fronted path only mentions the CDN host.
 */
export const setDirectAllowed: (allowed: boolean) => void;

export const apiLogin: (account: string, publicKey: string) => Promise<string>;

/** `{"ok":true,"devices":[...]}` or an error object. */
export const apiDevices: (token: string) => Promise<string>;

/** `{"ok":true}` or an error object. */
export const apiRemoveDevice: (token: string, deviceId: string) => Promise<string>;

/** `{"ok":true,"account":{"id","expiry"}}` or an error object. */
export const apiAccount: (token: string) => Promise<string>;

/**
 * Fetches the signed relay list and writes a flattened copy to `relays.json` in the app
 * files directory. Answers `{"ok":true,"path":...,"count":n}` or an error object.
 */
export const apiRelays: () => Promise<string>;

/**
 * Creates the unconnected UDP socket the WireGuard engine will use. The caller must pass
 * the returned fd to `VpnConnection.protect()` so the handshake leaves the device instead
 * of being routed back into the tunnel being built. Returns the fd, or negative on error.
 */
export const openRelaySocket: (family: number) => number;

/**
 * Starts the WireGuard engine on an already-created tun fd. Requires a socket from
 * `openRelaySocket` to have been created and protected; the engine takes ownership of it. The private key stays in the
 * native process. Answers `{"ok":true,"endpoint":"ip:port"}` or an error object.
 */
export const tunnelStart: (fd: number, mtu: number, peerKey: string, endpointIp: string,
  endpointPort: number, bridgeEndpoint: string) => string;

/** `{"running":bool,"inbound":bool,"error":""}` — `inbound` is the handshake proof. */
export const tunnelStatus: () => string;

export const tunnelStop: () => void;

/** Diagnostics logging is opt-in; off by default. */
export const setDiagnostics: (enabled: boolean) => void;

/** Starts a new diagnostics section (one per connection attempt). */
export const logMarker: (title: string) => void;

/** Appends one line to the current diagnostics section. */
export const logLine: (text: string) => void;
