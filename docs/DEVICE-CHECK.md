# Device check

What to run on the tablet after a build, in order. Each step names the state to look for and
the log line that proves it. Enable **Diagnostics** in settings first; the log is in the
app's files directory as `yanou-native.log` and is readable from the Diagnostics screen.

Install:

```sh
hdc install -r app/entry/build/default/outputs/default/entry-default-signed.hap
hdc shell aa start -b com.maxime.muharmony -a EntryAbility
```

## 1. Single hop

Connect with the default settings (IPv4 only, kill switch on, automatic protocol).

- UI: `Connected`, a relay name, a handshake time.
- Log: `tunnel: device up, asking for a handshake`, then `tunnel: handshake complete`.

## 2. Content blocking

Settings → DNS → automatic, and switch on **Ads**.

- Log: `dns: 100.64.0.1`, and the vNIC line shows that resolver.
- Query through the tunnel: `hdc shell "ping -c1 100.64.0.1"` should not fail at the route
  level, and an ad domain requested from the tablet's browser should be blocked.

## 3. Custom DNS

Settings → DNS → **Custom**, add a public resolver (for example `1.1.1.1`), connect.

- Log: `dns: 1.1.1.1` and no exclusion line.
- Add a private resolver (for example `192.168.1.1`): the log line must say
  `outside the tunnel: 192.168.1.1`, and the resolver must still answer.

## 4. Multihop

Settings → enable **Multihop**, then pick an **Exit relay** from the server browser.

- UI: configuration card shows `MTU 1360` and `Multihop · exit <city>`.
- Log: `tunnel: multihop mtu 1360 (1420 - 60 B second WireGuard header, floor 1280)`,
  then `tunnel: multihop handshake confirmed on both devices`.
- A large transfer (a file download) must not stall.

## 4b. DNS on the wire (open)

The resolver reaches `VpnConfig.dnsAddresses` and answers through the tunnel, but the system
resolver does not use it.

Evidence, all from one connected session with blocking on:

```
dns: auto · blocking mask 1 · 100.64.0.1      ← what the tunnel advertises
dns check: 10.64.0.1:53   -> 129 B            ← default resolver answers
dns check: 100.64.0.1:53  -> 33 B             ← blocking resolver answers, NXDOMAIN
dns check: doubleclick.net -> 2404:6800:…     ← connection.getAddressesByName ignores both
```

So the tunnel side is correct: a raw unprotected UDP query to the resolver gets the blocked
answer. `connection.getAddressesByName`, the app's own resolver path, still returns a real
address.

The reason is now measured, not guessed:

```
dns check: default net 219 dnses [202.113.15.2, 202.113.5.6, 2001:250:400:659::3]
```

The default network still carries the Wi-Fi resolvers. The VPN takes the routes but not the
default-network role, so netmanager answers lookups from the physical network's DNS and
`VpnConfig.dnsAddresses` is never consulted.

Next avenues, in order: check whether netmanager requires the resolver to be added to a
"network" rather than to the VPN config on this build; try `isInternal`; and if neither works,
carry DNS blocking in the tunnel itself (intercept port 53 in the core) rather than relying on
the platform resolver.

## 5. DAITA

Settings → DAITA on, then connect to a relay that advertises it.

- Log, in order: `daita: requested for this connection`, `daita: negotiating via
  10.64.0.1:1337`, `daita: relay returned <N> machine(s)`, `tunnel: daita active with <N>
  machine(s)`, `daita: engine reports DAITA active (<N> machine(s))`.
- Failure is loud and closes the connection: `result: failed · DAITA negotiation failed: ...`.

## 6. Transports

The ladder is `direct-v6, shadowsocks-v4, direct-v4, lwo-v4, lwo-v6, shadowsocks-v6,
udp2tcp-v4, udp2tcp-v6, quic-v4, quic-v6`. On a network that allows everything, only the
first rung is exercised; to prove the others, use **Protocol preference** to restrict the
ladder, and prefer **Obfuscated only** on a filtered network. The attempt line names the
transport: `attempt 3: <relay> <endpoint> ipv4 lwo v2`.
