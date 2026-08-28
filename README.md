<p align="center">
  <img src="https://github.com/colocohen/turn-server/raw/main/turn-server.svg" width="450" alt="turn-server"/>
</p>

<h1 align="center">turn-server</h1>
<p align="center">
  <em>Production-grade STUN/TURN server and client for Node.js</em>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/turn-server">
    <img src="https://img.shields.io/npm/v/turn-server?color=blue" alt="npm">
  </a>
  <img src="https://img.shields.io/github/license/colocohen/turn-server?color=brightgreen" alt="license">
</p>

---

> **⚠️ Project status: Active development.**
> APIs may change before v1.0. Use at your own risk and please report issues!

---


## Table of Contents
1. [What is STUN / TURN?](#-what-is-stun--turn)
2. [Why turn-server?](#-why-turn-server)
3. [Quick Start](#-quick-start)
4. [Features](#-features)
5. [ICE Agent](#-ice-agent)
6. [Hooks API](#-hooks-api)
7. [Client API](#-client-api)
8. [Comparison](#-comparison)
9. [Performance](#-performance)
10. [Interoperability Testing](#-interoperability-testing)
11. [Project Structure](#-project-structure)
12. [Roadmap](#-roadmap)
13. [Sponsors](#-sponsors)
14. [License](#-license)


## ⚡ What is STUN / TURN?

**STUN** (Session Traversal Utilities for NAT) and **TURN** (Traversal Using Relays around NAT) are the protocols that make real-time communication possible across the Internet. They are the foundation of **WebRTC** - every video call, screen share, and peer-to-peer connection relies on them.

The problem they solve:

- **NAT traversal**: Most devices sit behind NATs that block incoming connections. STUN lets a client discover its public IP and port. When direct connections fail, TURN relays traffic through a server.

- **Universal connectivity**: TURN guarantees that two peers can always communicate, even behind the most restrictive firewalls and symmetric NATs - by relaying through a server that both sides can reach.

- **ICE framework**: Interactive Connectivity Establishment (ICE) uses STUN and TURN together to find the best path between peers - direct if possible, relayed if necessary.

Every WebRTC application needs a STUN/TURN server. Google, Twilio, Cloudflare, and others operate massive TURN infrastructure. With **turn-server**, you can embed this capability directly into your Node.js application.


## 🧠 Why turn-server?

The existing options for STUN/TURN in Node.js are limited: **coturn** is a C daemon you run separately, **node-turn** is a minimal server with basic features, and the **stun** npm package only handles STUN (no TURN). None of them give you a complete, embeddable library with full protocol coverage.

**turn-server** is a from-scratch implementation of the complete STUN/TURN protocol stack - both client and server - built as a library you can `require()` into any Node.js application. It covers every RFC, every attribute, every edge case.

**What this means for you:**

- **`npm install` and go** - no build tools, no native binaries, no external daemons
- **Full control** - 14 hooks let you intercept every decision: authentication, authorization, relay routing, bandwidth, per-user quotas
- **Client + Server** - not just a server: includes `connect()`, `getPublicIP()`, NAT detection, DNS SRV, auto-refresh
- **Embeddable** - runs inside your Express/Fastify/Koa app, your Electron app, your CLI tool
- **Debuggable** - every packet, every attribute, every state transition is JavaScript you can step through


## 📦 Quick Start

```bash
npm install turn-server
```

> **Dependencies.** The core - STUN/TURN over UDP/TCP/TLS, server, client, and the ICE agent - is pure JavaScript. Two transports pull in pure-JS helpers, both **lazy-loaded** (only required when you actually use them):
> - **DTLS** (RFC 7350) uses [`lemon-tls`](https://www.npmjs.com/package/lemon-tls) - installed by default.
> - The optional WebSocket **server** auto-attach uses [`ws`](https://www.npmjs.com/package/ws) - an `optionalDependency`. The WebSocket **client** needs no dependency: it uses Node 22's built-in global `WebSocket`. You can also bring your own WebSocket server via `handleWebSocket()` (no `ws` needed).
>
> So UDP/TCP/TLS-only and BYO-WebSocket deployments carry no extra runtime cost.

### Server

```js
import { createServer } from 'turn-server';

const server = createServer({
  auth: {
    mechanism: 'long-term',
    realm: 'example.com',
    credentials: { alice: 'password123' }
  },
  relay: { ip: '0.0.0.0', externalIp: '203.0.113.5' }
});

server.on('listening', (info) => {
  console.log(`TURN server on ${info.address}:${info.port}/${info.transport}`);
});

server.listen({ port: 3478 });
```

### Server with REST API credentials (WebRTC)

```js
import { createServer } from 'turn-server';

const server = createServer({
  auth: {
    mechanism: 'long-term',
    realm: 'example.com',
    secret: 'your-shared-secret'   // TURN REST API - time-limited credentials
  },
  relay: { ip: '0.0.0.0', externalIp: '203.0.113.5' },

  // Production options
  maxConnections: 10000,
  userQuota: 10,
  totalQuota: 5000,
  maxDataSize: 65535,
  idleTimeout: 300000,             // 5 min - clean up dead UDP clients
  hookTimeout: 5000,               // budget for a hook that defers its decision
});

// Dynamic auth via hook (database lookup, etc.)
server.on('authenticate', (username, realm, cb) => {
  db.getHmacKey(username, realm).then(key => cb(key));
});

// Graceful shutdown
process.on('SIGTERM', () => {
  server.drain(30000, () => process.exit(0));
});

server.listen([
  { port: 3478 },                                         // UDP + TCP
  { port: 5349, transport: 'tls',  cert: CERT, key: KEY }, // TLS
  { port: 5349, transport: 'dtls', cert: CERT, key: KEY }, // DTLS (RFC 7350) - UDP
  { port: 8443, transport: 'ws' },                         // WebSocket (auto: needs `ws` installed)
]);
```

The WebSocket and DTLS endpoints are wired the same way as UDP/TCP/TLS - one
engine, one set of hooks. For WebSocket you can also attach to an existing
HTTP(S) server instead of letting the library open a port:

```js
import { WebSocketServer } from 'ws';

// Option A: hand turn-server the constructor + your http(s) server
server.listen([{ transport: 'ws', WebSocketServer, server: myHttpsServer }]);

// Option B: full BYO - drive the upgrade yourself (Express/Fastify friendly)
const wss = new WebSocketServer({ server: myHttpsServer, path: '/turn' });
wss.on('connection', (ws, req) => server.handleWebSocket(ws, req));
```

> WebSocket rides on the HTTP/1.1 Upgrade mechanism. If your app is HTTP/2, run
> the WS endpoint on an HTTP/1.1 listener (same host/cert is fine) - `ws` does
> not support WebSocket-over-HTTP/2 (RFC 8441).

#### Shared TLS material

`tls` and `dtls` endpoints inherit a server-level default, so you can set the
certificate once instead of per endpoint (the per-endpoint config still wins):

```js
const server = createServer({
  auth: { /* ... */ }, relay: { /* ... */ },
  tls: { cert: CERT, key: KEY, SNICallback },   // inherited by every tls + dtls endpoint
});
server.listen([
  { port: 5349, transport: 'tls' },             // uses the shared cert/key
  { port: 5349, transport: 'dtls' },            // same
]);
```

#### DTLS / STUN on one shared UDP socket (RFC 7983)

In external-socket mode you feed one UDP socket through `handlePacket()`. With a
`dtls` config, that socket demuxes by first byte (RFC 7983): cleartext STUN/TURN
and DTLS-to-server (RFC 7350) coexist on the same port - useful when bundling
with QUIC/other protocols behind one port.

```js
const udp = dgram.createSocket('udp4');
udp.bind(3478, () => {
  const server = createServer({
    socket: udp,                                 // external/shared socket mode
    auth: { /* ... */ }, relay: { /* ... */ },
    dtls: { cert: CERT, key: KEY, SNICallback }, // also accept DTLS on this socket
  });
  udp.on('message', (msg, rinfo) => server.handlePacket(msg, rinfo));
});
```

### Client - get your public IP

```js
import { getPublicIP } from 'turn-server';

getPublicIP((err, info) => {
  console.log('My public IP:', info.ip);     // "203.0.113.42"
  console.log('Mapped port:', info.port);    // 54321
});
```

### Client - allocate a TURN relay

```js
import { connect } from 'turn-server';

const client = connect('turn:turn.example.com:3478?transport=udp', {
  username: 'alice',
  password: 'password123',
}, (err, socket) => {
  socket.allocate({ lifetime: 600 });

  socket.on('allocate:success', (msg) => {
    const relay = msg.getAttribute(0x0016);  // XOR-RELAYED-ADDRESS
    console.log('Relay address:', relay.ip, relay.port);
  });

  // Receive data from peers
  socket.on('data', (peer, data) => {
    console.log(`Data from ${peer.ip}:${peer.port}:`, data);
  });
});
```

The transport is chosen by the URI (RFC 7064 / 7065 / 7350):

```js
connect('turn:host:3478?transport=udp',  opts, cb);  // UDP
connect('turn:host:3478?transport=tcp',  opts, cb);  // TCP
connect('turns:host:5349?transport=tcp', opts, cb);  // TLS over TCP
connect('turns:host:5349?transport=udp', opts, cb);  // DTLS  (RFC 7350)
connect('wss://host:8443/turn',          opts, cb);  // WebSocket over TLS
```

Every form returns the same `socket` with the same API (`allocate`,
`createPermission`, `channelBind`, `send`, the `data` event) - the transport is
transparent to the protocol layer.


## ✨ Features

### Wire Protocol (RFC 8489 / 8656)
- 62 STUN/TURN attributes with full encode/decode - every IANA-registered type
- 11 methods: BINDING, ALLOCATE, REFRESH, SEND, DATA, CREATE_PERMISSION, CHANNEL_BIND, CONNECT, CONNECTION_BIND, CONNECTION_ATTEMPT, GOOG_PING
- MESSAGE-INTEGRITY (SHA1), MESSAGE-INTEGRITY-SHA256, SHA384, SHA512
- FINGERPRINT (CRC32 with XOR), timing-safe comparison
- ChannelData encode/decode (zero-copy subarray)
- STUN-over-stream framing (RFC 8489 §6.2.2) - self-delimiting, no length prefix (matches coturn and browsers)
- STUN/TURN URI parsing (RFC 7064 / 7065)
- SASLprep / NFKC normalization
- RFC 5769 test vectors - 22/22 passing

### Server
- Multi-endpoint: UDP, TCP, TLS, WebSocket, DTLS on any combination of ports
- 4 auth mechanisms: none, short-term, long-term, OAuth (RFC 7635)
- REST API credentials (shared secret, time-limited)
- PASSWORD-ALGORITHMS negotiation with bid-down attack prevention
- Structured nonces bound to source address (replay prevention)
- Fingerprint mirroring - server mirrors client's FINGERPRINT usage per-session
- SNICallback for multi-domain TLS (like `node:tls`)
- realmCallback for per-client realm/auth configuration
- relayCallback for per-allocation relay address selection
- EVEN-PORT and RESERVATION-TOKEN (RFC 5766 §14.6 / §14.9) - even-port allocation, port+1 reservation with the token returned in the Allocate response, cross-connection claim, 30-second reservation TTL
- ICMP error forwarding (RFC 8656 §11.5) - relay send failures become Data indications carrying an ICMP attribute; the client surfaces them as an `icmp` event
- TCP relay (RFC 6062) - CONNECT and CONNECTION_BIND
- NAT behavior discovery (RFC 5780) - CHANGE-REQUEST with secondary address
- Peer address blocking - loopback, multicast, unspecified blocked by default (CVE-2020-26262)
- Origin consistency checking

### Server - Production Features
- Built-in convenience limits: `maxConnections` (enforced on **every** transport: UDP, TCP, TLS, WebSocket, DTLS), `userQuota`, `totalQuota`, `maxDataSize`, `maxPermissionsPerAllocation`, `maxChannelsPerAllocation` - each answering the RFC error code the client actually needs (486 / 508), not a blanket 403
- Async hooks - every admission decision (`accept`, `authorize`, `beforeAllocate`, `beforeRefresh`, `beforePermission`, `beforeChannelBind`, `beforeConnect`, `beforeBindingResponse`) can await a database or Redis lookup; only the two per-packet relay hooks stay synchronous. A hook that never answers fails closed on a configurable `hookTimeout`
- `beforeBindingResponse` hook - gate every STUN Binding reply to close the reflection/amplification vector, keyed on a source prefix
- Per-allocation packet counters (`packetsIn` / `packetsOut`) alongside bytes, via `getBandwidth()`
- UDP idle timeout - automatically removes dead 5-tuple entries (default 5 min)
- Graceful shutdown - `drain(timeout, cb)` stops new connections on all transports, waits for existing
- Statistics - `getStats()` returns 7 real-time counters, including a live `authFailures` count
- `auth:failure` event - `(socket, { username, code, reason })` on bad integrity / unknown user / wrong credentials (the initial 401 challenge of the normal long-term flow is *not* counted) - ideal for rate limiting or fail2ban-style banning
- Health check - `isHealthy()`, `isDraining()`
- TLS with ALPN (`stun.turn`, `stun.nat-discovery`) and SNI

### Client
- `connect(uri, options, cb)` - like `tls.connect()`, URI-based with DNS SRV
- `getPublicIP(cb)` - STUN binding one-liner (defaults to Google STUN)
- `detectNAT(server, cb)` - RFC 5780 NAT type detection (full-cone, restricted, symmetric)
- `resolve(uri, cb)` - DNS SRV lookup (`_turn._udp.example.com`)
- Auto-refresh timers - allocation (lifetime-60s), permissions (4min), channels (9min)
- UDP retransmission with exponential backoff (Rc=7, Rm=16, configurable RTO)
- TCP transaction timeout (Ti=39.5s default)
- Auto-retry on 401 Unauthorized and 438 Stale Nonce
- 300 Try Alternate redirect handling
- Transaction ID validation on responses

### ICE Agent (RFC 8445 / 7675 / 8839)
- **Full and Lite modes** - Full initiates checks (clients, SFU gateways); Lite only responds (server-side ICE per RFC 8445 §2.4)
- **Vanilla and Trickle gathering** - emit candidates incrementally or batch until complete
- **Candidate types** - host, server-reflexive (srflx), peer-reflexive (prflx), relay (TURN) - IPv4 and IPv6
- **Multi-homed gathering** - srflx fan-out per host base (RFC 8445 §5.1.1.1) across all interfaces
- **Multiple ICE servers** - mixing STUN + TURN, multiple TURN servers, multiple URIs per server - all gathered in parallel with graceful degradation on failures
- **Regular nomination** - controlling agent uses USE-CANDIDATE (RFC 8445 §8.1.1.1)
- **Peer-reflexive construction** - symmetric NAT handling per RFC 8445 §7.2.5.3 (new valid pair with prflx local, not re-marking original)
- **Role conflict resolution** - RFC 8445 §7.3.1.1 tie-breaker with 487 error responses and role-flip
- **Consent freshness** (RFC 7675) - 15s interval with ±20% jitter, disconnected at 30s, failed at 45s
- **ICE restart** (RFC 8445 §9) - seamless media continuity via previous-pair fallback; `agent.send()` keeps working during restart window
- **iceTransportPolicy** - `'all'` or `'relay'` (TURN-only, for privacy/firewall scenarios)
- **MESSAGE-INTEGRITY validation** on 401/438/487 error responses (prevents role-flip spoofing)
- **Link-local filtering** - skips 169.254.x.x (RFC 3927) and IPv6 fe80:: / 100::
- **mDNS candidates** (draft-ietf-mmusic-mdns-ice-candidates) - resolves the concealed `.local` candidates every modern browser sends, and can conceal your own host candidates behind UUID names (`register` mode, for privacy-sensitive clients). Strict draft compliance: UUID-only resolution (hostile `printer.local` candidates are rejected), single-IP rule, relay-policy exclusion
- **Port-mapping assisted gathering** (UPnP-IGD / NAT-PMP / PCP via [`port-mapper`](https://npmjs.com/package/port-mapper)) - asks the gateway to forward a port and advertises the external address as an srflx candidate. A real forwarding rule works from **any** peer - including behind symmetric NAT, where STUN srflx is per-destination and near-useless. Often yields a direct connection with **no STUN and no TURN server at all**


## 🧰 ICE Agent

A complete **RFC 8445** ICE agent, usable standalone or as the ICE layer for a full WebRTC stack. Exposed as `IceAgent`, with a reactive event-driven API that mirrors the patterns of `RTCPeerConnection.iceTransports[0]`.

### Minimal usage

```js
import { IceAgent } from 'turn-server';

const agent = new IceAgent({
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'turn:turn.example.com:3478', username: 'alice', credential: 'secret' },
  ],
  mode: 'full',        // 'full' | 'lite'
  trickle: true,
  controlling: true,   // offerer = true, answerer = false
});

// Local credentials (auto-generated, or supply in constructor)
const { ufrag, pwd } = agent.localParameters;

// Candidate discovery
agent.on('candidate', (c) => {
  if (c === null) { /* end-of-candidates */ return; }
  signaling.sendCandidate(c);
});

// State transitions: new → checking → connected → disconnected → failed
agent.on('statechange',  (next, prev) => console.log('ICE:', prev, '→', next));
agent.on('selectedpair', (pair) => console.log('Using', pair.local.ip, '→', pair.remote.ip));
agent.on('packet',       (buf, rinfo, type) => { /* DTLS / RTP / RTCP */ });

// Peer exchange
agent.setRemoteParameters({ ufrag: peerUfrag, pwd: peerPwd });
for (const c of peerCandidates) agent.addRemoteCandidate(c);
agent.addRemoteCandidate(null);   // end-of-candidates

agent.gather();                   // start gathering host + srflx + relay
// after 'selectedpair':
agent.send(Buffer.from('hello'));
```

### Configuration

| Option | Default | Description |
|---|---|---|
| `iceServers` | `[]` | Array of `{ urls, username?, credential? }` (WebRTC API format) |
| `mode` | `'full'` | `'full'` (sends + receives checks) or `'lite'` (only receives; for SFUs) |
| `trickle` | `true` | Emit candidates as found (`true`) or batch until complete (`false`) |
| `controlling` | `true` | `true` = offerer (sends USE-CANDIDATE), `false` = answerer |
| `iceTransportPolicy` | `'all'` | `'all'` (host + srflx + relay) or `'relay'` (only TURN) |
| `includeLoopback` | `false` | Include `127.0.0.1` / `::1` in host candidates (testing only) |
| `ipv6` | `true` | Gather IPv6 candidates |
| `ufrag` / `pwd` | auto | Local credentials (auto-generated if omitted; 24-bit ufrag, 128-bit pwd) |

`iceServers[].urls` can be a string or an array. Each URL can carry `?transport=udp|tcp`. For `turns://` URLs, additional TLS options `servername`, `rejectUnauthorized`, `ca` are honored.

### Events

| Event | Payload | When |
|---|---|---|
| `candidate` | `(cand)` | Each local candidate found; `null` signals end-of-candidates |
| `statechange` | `(next, prev)` | `new` / `checking` / `connected` / `disconnected` / `failed` / `closed` |
| `gatheringstatechange` | `(next, prev)` | `new` / `gathering` / `complete` |
| `selectedpair` | `(pair, prev?)` | A valid pair was nominated and selected |
| `paircheck` | `(pair, success)` | A connectivity check completed |
| `packet` | `(buf, rinfo, type)` | Non-STUN payload (DTLS/RTP/RTCP/channel-data) |
| `candidateerror` | `(error)` | Gathering a srflx/relay candidate failed (e.g., STUN timeout, TURN auth) |
| `rolechange` | `('controlling' \| 'controlled')` | Role flipped (RFC 8445 §7.3.1.1) |
| `restart` | `({ ufrag, pwd })` | `agent.restart()` was called |

### Candidate sources beyond STUN/TURN

Most ICE stacks know exactly two ways to discover an address: ask a STUN
server, or allocate a TURN relay. This agent has **four**:

| Source | Produces | Works when | Needs a server? |
|---|---|---|---|
| Host interfaces | `host` | always | no |
| STUN binding | `srflx` | NAT is well-behaved (fails behind symmetric NAT) | yes |
| TURN allocation | `relay` | always | yes (and relays all traffic) |
| **Gateway port mapping** (UPnP/NAT-PMP/PCP) | `srflx` | gateway cooperates (~most home/SOHO routers) | **no** |

Plus **mDNS**, which is not a new source but makes the sources you have
actually usable: browsers conceal their host candidates behind `.local`
names, and an agent that cannot resolve them silently loses every LAN
direct path. This agent resolves them (and can conceal its own).

Why this matters in practice:

- **P2P without infrastructure.** A port-mapped candidate is a real
  forwarding rule on the router - reachable by any peer, resilient to
  symmetric NAT, no third-party server in the media path and none in the
  discovery path either. For Electron/desktop P2P apps this is the same
  trick qBittorrent and Syncthing ship by default, applied to WebRTC.
- **LAN connections that browsers can complete.** Chrome/Safari/Firefox
  send only `.local` host candidates. Resolving them is the difference
  between a 0.5ms direct LAN path and bouncing everything off a relay.
- **Defense in depth.** All four sources gather **in parallel**; ICE picks
  the best pair that actually verifies. Add STUN/TURN servers and they
  compose - the mapping is simply one more (usually better) srflx.

```js
const agent = new IceAgent({
  iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
  mdns: true,               // resolve browsers' .local candidates
  portMapping: true,        // + gateway-assisted srflx (opt-in here;
                            //   webrtc-server enables it for clients)
});

// Privacy-sensitive client (Electron): also conceal our own addresses
const agent2 = new IceAgent({
  mdns: { register: true },        // host candidates go out as UUID .local
  portMapping: { description: 'MyApp' },   // shown in the router's UI
});
```

Both features are lazy `optionalDependencies` ([`mdns-local`](https://npmjs.com/package/mdns-local),
[`port-mapper`](https://npmjs.com/package/port-mapper)) - nothing loads,
no socket binds, and no router is spoken to unless the option is enabled.
Both accept `{ instance }` injection if your app already runs one, and both
share one process-wide instance across any number of agents (refcounted -
an SFU with 200 agents does not open 200 multicast sockets).

Behavior by configuration:

| | `mode: 'full'` | `mode: 'lite'` | `iceTransportPolicy: 'relay'` |
|---|---|---|---|
| resolve inbound `.local` | ✅ when enabled | ignored (lite learns peers from inbound checks) | ignored (draft rule) |
| `register` concealment | ✅ opt-in | forced off | n/a |
| port-mapping gathering | ✅ when enabled | forced off | forced off (srflx-class) |

Failures never block: CGNAT / double-NAT is detected at negotiation
(one informative `candidateerror`, zero wasted mappings), a silent gateway
is abandoned on a ~3s budget (NAT-PMP's retransmission tail alone can run
minutes), and an unresolvable `.local` name just means that one path is
skipped.

### Multiple ICE servers

Pass as many as you want. Host/srflx/relay candidates are gathered from **every** server **in parallel**:

```js
new IceAgent({
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun.cloudflare.com:3478' },
    { urls: 'turn:turn1.example.com:3478',     username: 'u1', credential: 'p1' },
    { urls: 'turn:turn2.example.com:3478',     username: 'u2', credential: 'p2' },
    { urls: 'turns:turn-tls.example.com:5349', username: 'u3', credential: 'p3' },
  ],
});
```

If some servers fail (timeout, auth error), `candidateerror` is emitted per failure and the agent proceeds with whatever candidates did come back. ICE then picks the best pair by priority (host > srflx > relay, RFC 8445 §5.1.2).

### ICE restart (RFC 8445 §9)

Unlike the "hard reset" approach used by pion/werift/aioice (which clears `selectedPair` immediately and interrupts media for 1-3 seconds), this agent implements **seamless restart** per RFC 8445 §9:

```js
const { ufrag, pwd } = agent.restart();
// - Clears check state + remote creds
// - Moves the OLD selectedPair to an internal _previousPair
// - agent.send() keeps flowing via _previousPair during the restart window

// Signal the new local creds to the peer via your SDP layer
signaling.sendRestartOffer(ufrag, pwd);
const answer = await signaling.receiveRestartAnswer();

agent.setRemoteParameters({ ufrag: answer.ufrag, pwd: answer.pwd });
for (const c of answer.candidates) agent.addRemoteCandidate(c);
agent.gather();

// When a new pair wins nomination, selection switches automatically.
// _previousPair is dropped; agent.send() seamlessly switches to the new pair.
```

The result is **zero packet loss during restart** when the old path is still functional (e.g., user-initiated restart). For restarts triggered by a dead path (~85% of real-world restarts), the behavior matches the hard-reset approach.

`gather()` after a restart:
- **Re-announces the kept candidates** through the `candidate` event, so the SDP layer sees the full set again (existing sockets are preserved - they carry the previous pair's media during the restart window).
- **Binds sockets only for interfaces that appeared** since the previous gather - the network-change case, which is the most common reason to restart ICE.
- **Reuses live TURN allocations** instead of allocating a second time on the same server.

### Using IceAgent with your own TURN client socket

If you already have a `Socket` (from `connect()` or a custom transport), pass it as `externalSocket`:

```js
import { connect, IceAgent } from 'turn-server';

connect('turn:my-turn.example.com:3478', { username: 'u', password: 'p' }, (err, sock) => {
  const agent = new IceAgent({
    externalSocket: sock,     // IceAgent will not bind its own sockets
    iceServers: [],           // no extra gathering
    mode: 'full',
    controlling: true,
  });
  agent.gather();
});
```



## 🪝 Hooks API

Every decision point in the server is exposed as a hook. Hooks receive an info object and a callback. If no listener is attached, the action is auto-approved.

```js
cb(true)                          // allow
cb(false)                         // deny with the hook's default error code
cb(false, 486)                    // deny with a specific code
cb(false, 508, 'No capacity')     // deny with a code and a reason phrase
```

**Almost every hook may answer asynchronously.** Nothing is sent and no state changes until `cb` fires, so a database or Redis lookup inside a listener is safe:

```js
server.on('accept', (info, cb) => {
  // info: { source: { ip, port }, transport: 'udp'|'tcp'|'tls'|'ws'|'dtls' }
  cb(isAllowed(info.source.ip));
});

server.on('beforeAllocate', async (info, cb) => {
  // info: { username, source, transport, lifetime, ... }
  const count = await db.countAllocations(info.username);
  if (count >= 5) return cb(false, 486, 'Per-user allocation quota exceeded');
  info.lifetime = 300;              // hooks may also modify the lifetime
  cb(true);
});
```

The two exceptions are the **relay hot path** - `beforeRelay` and `beforeData` run once per relayed packet, so they must answer in the same tick:

```js
server.on('beforeRelay', (info, cb) => {
  cb(bucket.take(info.username));   // in-memory only — never await here
});
```

That split is deliberate. A busy relay moves tens of thousands of packets per second; a round trip to Redis per packet is not merely slow, it is arithmetically impossible on one event loop. Keep per-packet state in memory (a local token bucket, a `Map`, or a `SharedArrayBuffer` with `Atomics` if you shard across `worker_threads`) and reserve async lookups for the rare decisions: `accept`, `authenticate`, `beforeAllocate`.

### Timeouts and failure mode

A listener that never calls `cb` would otherwise pin the request forever, so the decision **fails closed** once `hookTimeout` elapses:

```js
createServer({ hookTimeout: 5000 });   // default 5000 ms
```

A listener that answers synchronously never touches the timer or the event loop, so existing synchronous listeners keep their current behaviour and cost. Upgrading to async requires no code change on your side.

### What happens to traffic while a hook is pending

`accept` gates a connection before it exists, so each transport has to decide what to do with bytes that arrive during the decision:

| Transport | Behaviour | Why |
|---|---|---|
| UDP | dropped | The source is spoofable at this point, so queuing would let an attacker grow the heap for free. STUN retransmits, so a legitimate client recovers. |
| DTLS (shared socket) | dropped | Same - the hook fires on the first datagram, before any handshake. DTLS retransmits its ClientHello. |
| TCP / TLS | held | The stream is paused until the decision lands; the kernel and the stream's high-water mark apply backpressure. No bytes are lost. |
| WebSocket / DTLS (dedicated port) | held (max 32 frames) | The handshake already completed, so the source is verified - and STUN over a reliable transport has no per-request retransmission, so a dropped frame would stall the client until Ti (39.5s). |

A burst from one UDP 5-tuple triggers the `accept` hook **once**, not once per packet.

### Rejection codes

Passing a code lets you return the error the client actually needs, instead of a blanket 403:

| Hook | Default | Also useful |
|---|---|---|
| `authorize` | 403 Forbidden | - |
| `beforeAllocate` | 403 Forbidden | 486 Allocation Quota Reached, 508 Insufficient Capacity |
| `beforeRefresh` | 403 Forbidden | 437 Allocation Mismatch, 508 Insufficient Capacity |
| `beforePermission` | 403 Forbidden | 508 Insufficient Capacity |
| `beforeChannelBind` | 403 Forbidden | 400 Bad Request, 441 Wrong Credentials |
| `beforeConnect` | 403 Forbidden | 446 Connection Already Exists, 447 Connection Timeout or Failure |
| `quota` | 486 Allocation Quota Reached | 508 Insufficient Capacity |
| `accept`, `beforeBindingResponse` | silent drop | n/a - no response is sent, so a code would have nowhere to go |
| `beforeRelay`, `beforeData` | silent drop | n/a |

The built-in limits use these too: `totalQuota` and `userQuota` now answer 486, and `maxPermissionsPerAllocation` / `maxChannelsPerAllocation` answer 508.

### `beforeBindingResponse` - closing the amplification vector

A Binding response is larger than the request that triggered it, and the source address of a UDP request is trivially spoofed. An open Binding responder is therefore a reflection amplifier: an attacker sends ~20 bytes with the victim's address and the server sends ~40 bytes to the victim.

This hook fires before the response is generated. Rejecting sends **nothing at all** - not even an error, since an error response is itself an amplified reply:

```js
server.on('beforeBindingResponse', (info, cb) => {
  // Key on a source PREFIX, not the exact address: the source is spoofed,
  // so blocking a single IP achieves nothing.
  cb(bindingBucket.take(prefix(info.source.ip)));   // /24 for IPv4, /56 for IPv6
});
```

`accept` also fires per UDP 5-tuple, but only once; this hook runs before every response.

### The `authenticate` hook - sync or async, one contract

`authenticate` resolves credentials for **both** long-term and short-term auth,
with a single callback contract. Both styles are accepted:

```js
cb(passwordOrKey)        // password string, pre-computed HMAC key (Buffer), null = unknown user
cb(err, passwordOrKey)   // Node style - err → treated as unknown user
```

The callback may be invoked **synchronously or asynchronously** - the server
defers its response until the callback fires, so database lookups are safe.
Only the first invocation counts. For long-term auth, a string is passed
through `MD5(user:realm:pass)` key derivation; a Buffer is used verbatim as
a pre-computed key. For short-term auth, a string is the raw password
(e.g. ICE's `ice-pwd`) and a Buffer is used verbatim.

Real failed attempts (bad integrity, unknown user, wrong credentials) emit
`auth:failure` and increment `getStats().authFailures`:

```js
server.on('auth:failure', (socket, { username, code, reason }) => {
  // reason: 'bad-integrity' | 'unknown-user' | 'wrong-credentials'
  //       | 'algorithm-mismatch' | 'invalid-token' | 'missing-credentials'
  banCandidates.record(socket.context.session?.context?.source, username);
});
```

All 15 hooks:

| Hook | When | Async? | Info |
|------|------|:---:|------|
| `accept` | New connection / UDP 5-tuple | ✅ | source, transport |
| `beforeBindingResponse` | Before answering a STUN Binding | ✅ | source, transport |
| `authenticate` | Long-term **and** short-term auth | ✅ | username, realm → cb(passwordOrKey) or cb(err, passwordOrKey) |
| `authenticate_oauth` | OAuth auth | ✅ | token, realm → cb(err, key) |
| `authorize` | After auth, before the method runs | ✅ | method, methodName, username, source |
| `quota` | Before allocate | ✅ | username → cb(allowed) |
| `beforeAllocate` | Allocate request | ✅ | username, source, transport, lifetime, requestedFamily, evenPort, reservationToken, dontFragment |
| `beforeRefresh` | Refresh request | ✅ | username, source, lifetime, currentLifetime |
| `beforePermission` | Permission request (once **per peer**) | ✅ | username, source, peer |
| `beforeChannelBind` | Channel bind | ✅ | username, source, channel, peer |
| `beforeConnect` | TCP connect (6062) | ✅ | username, source, peer |
| `beforeRelay` | Data relay (out) - **hot path** | ❌ sync | username, source, peer, size, direction, channel |
| `beforeData` | Data relay (in) - **hot path** | ❌ sync | peer, source, username, size, direction |
| `onRelayed` | After relay (notification) | n/a | direction, peer, size |
| `redirect` | Client got 300 | n/a | server, domain |

`beforePermission` fires once for each peer in a CreatePermission request and the walk stops at the first rejection - CreatePermission is all-or-nothing (RFC 8656 §9.2), so no permission is installed if any peer is denied.

Hooks and built-in limits work together - built-in checks run first, then your hook is called. Set a limit to `0` (default) to disable the built-in check and handle it entirely in your hook.

### Rate limiting

The library ships hooks, not policy: thresholds, keying and the bucket itself stay in your application. The three protocols fail in different ways, so they want different keys:

- **TURN is a resource-over-time problem.** An allocation holds a relay port and moves bytes for its whole lifetime. Key on `username`, decide at `beforeAllocate`, and count what actually flows with `getBandwidth()`.
- **STUN is an amplification vector.** The source address is spoofed, so key on a source *prefix* (`/24`, `/56`) at `beforeBindingResponse` - blocking a single address accomplishes nothing.
- **ICE needs nothing extra server-side.** ICE rides on STUN and TURN underneath; protecting those protects it.

```js
import { createServer } from 'turn-server';

const bindings = new TokenBucket({ rate: 50, burst: 100 });   // per /24, in memory
const relayed  = new TokenBucket({ rate: 5e6, burst: 1e7 });  // per username, in memory

const server = createServer({ auth: { /* ... */ }, relay: { /* ... */ } });

// Amplification: silent drop, keyed on a prefix.
server.on('beforeBindingResponse', (info, cb) => cb(bindings.take(prefix24(info.source.ip))));

// Brute force: the server tells you about failures it detected itself.
server.on('auth:failure', (sock, { username, reason }) => {
  if (reason === 'bad-integrity' || reason === 'unknown-user') fail2ban.record(sock);
});

// Allocation admission: rare, so an async lookup is fine here.
server.on('beforeAllocate', async (info, cb) => {
  const n = await db.countAllocations(info.username);
  if (n >= 5) return cb(false, 486, 'Per-user allocation quota exceeded');
  cb(true);
});

// Throughput: hot path, so the bucket must be in memory.
server.on('beforeRelay', (info, cb) => cb(relayed.take(info.username, info.size)));
```

`auth:failure` matters because it reports something you cannot otherwise observe. When your `authenticate` hook returns the correct key, you have said "this user exists" - the server then compares the HMAC and may still fail. That failure never reaches your code, which is exactly the blind spot a password-guessing attack lives in. The event fires on `bad-integrity`, `unknown-user`, `wrong-credentials`, `algorithm-mismatch`, `invalid-token` and `missing-credentials`, and never on the normal 401 challenge that begins every long-term handshake. Rejections your own hooks issued are not reported - you already know about those.

Per-allocation counters, live:

```js
server.on('connection', (sock) => {
  setInterval(() => {
    const { bytesIn, bytesOut, packetsIn, packetsOut } = sock.getSession().getBandwidth();
    // Packets matter independently of bytes: 1 MB in one packet and 1 MB in
    // 10,000 packets cost very different amounts of CPU, and the second is a
    // flood signature.
  }, 1000);
});
```

**Sharing a bucket across threads.** The hot-path hooks are synchronous, so a shared bucket cannot be reached over IPC or Redis - those are async by construction. Use a `SharedArrayBuffer` with `Atomics`, which is synchronous because the operations run directly on the CPU. Across separate *processes* that option is gone, and you either accept per-process limits or push the decision up to the rare hooks, where async is available.


## 🔌 Client API

### connect(uri, options, cb)

```js
import { connect } from 'turn-server';

// Supports RFC 7064/7065 URIs
connect('turn:example.com:3478?transport=udp', {
  username: 'alice',
  password: 'secret',
  autoRefresh: true,   // default - auto-refresh allocation, permissions, channels
}, (err, socket) => {
  socket.allocate();
  socket.createPermission([{ ip: '10.0.0.1', port: 5000 }]);
  socket.channelBind(0x4001, { ip: '10.0.0.1', port: 5000 });
  socket.sendChannel(0x4001, Buffer.from('hello'));

  socket.on('data', (peer, data, channel) => { /* ... */ });

  // ICMP errors from the relay path (RFC 8656 §11.5) - the server tells you
  // a Send to this peer bounced (port/host/net unreachable, packet too big)
  socket.on('icmp', (peer, icmp) => {
    console.log(`peer ${peer.ip}:${peer.port} unreachable`, icmp); // { type, code, data }
  });
});
```

#### allocate(options, cb)

| Option | Description |
|---|---|
| `transport` | `17` (UDP relay, default) or `6` (TCP relay, RFC 6062) |
| `lifetime` | Requested allocation lifetime in seconds |
| `dontFragment` | Add DONT-FRAGMENT |
| `evenPort` | `true` = even relay port **and** reserve port+1 (R bit); `{ reserve: false }` = even port only (RFC 5766 §14.6) |
| `reservationToken` | 8-byte token from a previous EVEN-PORT allocation - claims the reserved port+1 (RFC 5766 §14.9) |
| `requestedAddressFamily` | `0x01` IPv4 / `0x02` IPv6 (RFC 6156) |

The reservation flow (e.g. RTP on an even port, RTCP on the next odd port):

```js
rtpSocket.allocate({ evenPort: true });
rtpSocket.on('allocate:success', (msg) => {
  const relay = msg.getAttribute(0x0016);  // XOR-RELAYED-ADDRESS - even port
  const token = msg.getAttribute(0x0022);  // RESERVATION-TOKEN - 8 bytes

  // Any connection may claim relay.port+1 within 30 seconds:
  rtcpSocket.allocate({ reservationToken: token });
});
```

### getPublicIP(server?, cb)

```js
import { getPublicIP } from 'turn-server';

// Default: Google's public STUN server
getPublicIP((err, info) => {
  console.log(info);  // { ip: '203.0.113.42', port: 54321, family: 1 }
});

// Custom server
getPublicIP('stun:stun.example.com:3478', (err, info) => { /* ... */ });
```

### detectNAT(server, cb)

```js
import { detectNAT } from 'turn-server';

detectNAT('stun:stun.example.com:3478', (err, result) => {
  console.log(result.type);           // 'full-cone' | 'restricted-cone' | 'symmetric-or-port-restricted'
  console.log(result.mappedAddress);   // { ip, port }
});
```

### resolve(uri, cb)

```js
import { resolve } from 'turn-server';

// DNS SRV: _turn._udp.example.com
resolve('turn:example.com', (err, parsed) => {
  console.log(parsed);  // { host: '10.0.0.5', port: 3478, transport: 'udp', secure: false }
});
```


## 📊 Comparison

| | **turn-server** | **node-turn** | **stun** (npm) | **coturn** |
|---|:---:|:---:|:---:|:---:|
| **Language** | Node.js | Node.js | Node.js | C |
| **Dependencies** | **2** (pure JS) | 0 | 5+ | OpenSSL, DB |
| **Embeddable** | ✅ library | ✅ | ✅ | ❌ daemon |
| **ESM** | ✅ | ❌ CJS | ❌ CJS | N/A |
| **Maintained** | ✅ | ❌ 5yr | ❌ 6yr | ✅ |
| | | | | |
| **STUN (RFC 8489)** | ✅ full | partial | partial | ✅ |
| **TURN (RFC 8656)** | ✅ full | partial | ❌ | ✅ |
| **TCP relay (RFC 6062)** | ✅ | ❌ | ❌ | ✅ |
| **NAT detection (RFC 5780)** | ✅ | ❌ | ❌ | ✅ |
| **OAuth (RFC 7635)** | ✅ | ❌ | ❌ | ✅ |
| **ICE attrs (RFC 8445)** | ✅ | ❌ | ❌ | ✅ |
| **ICE agent (RFC 8445)** | ✅ full + lite | ❌ | ❌ | ✅ |
| **Consent freshness (RFC 7675)** | ✅ | ❌ | ❌ | ✅ |
| **ICE restart (RFC 8445 §9)** | ✅ seamless | ❌ | ❌ | ✅ |
| **mDNS candidates (browser `.local`)** | ✅ resolve + conceal | ❌ | ❌ | ❌ |
| **Port-mapping gathering (UPnP/PMP/PCP)** | ✅ | ❌ | ❌ | ❌ |
| **RFC 5769 test vectors** | ✅ 22/22 | ❌ | ✅ | ✅ |
| **Attributes** | 62 | ~8 | ~15 | 62+ |
| | | | | |
| **Short-term auth** | ✅ | ✅ | ✅ | ✅ |
| **Long-term auth** | ✅ | ✅ | ❌ | ✅ |
| **REST API (secret)** | ✅ | ❌ | ❌ | ✅ |
| **OAuth** | ✅ | ❌ | ❌ | ✅ |
| **SHA256 integrity** | ✅ | ❌ | ❌ | ✅ |
| **PASSWORD-ALGORITHMS** | ✅ | ❌ | ❌ | ✅ |
| **Bid-down prevention** | ✅ | ❌ | ❌ | ✅ |
| | | | | |
| **UDP** | ✅ | ✅ | ✅ | ✅ |
| **TCP + framing** | ✅ | ❌ | ❌ | ✅ |
| **TLS (ALPN + SNI)** | ✅ | ❌ | ❌ | ✅ |
| **WebSocket** | ✅ | ❌ | ❌ | ❌ |
| **DTLS** (RFC 7350) | ✅ | ❌ | ❌ | ✅ |
| | | | | |
| **Client connect()** | ✅ | ❌ | ✅ | ✅ uclient |
| **getPublicIP()** | ✅ | ❌ | ✅ | ❌ |
| **NAT detection** | ✅ | ❌ | ❌ | ❌ |
| **DNS SRV** | ✅ | ❌ | ❌ | ❌ |
| **Auto-refresh** | ✅ | ❌ | ❌ | ✅ |
| | | | | |
| **Hooks API** | ✅ 15 hooks, async | ❌ | ❌ | ❌ |
| **Convenience limits** | ✅ 6 options | ❌ | ❌ | ✅ config |
| **Idle timeout** | ✅ | ❌ | ❌ | ✅ |
| **Graceful drain** | ✅ | ❌ | ❌ | ❌ |
| **Stats counters** | ✅ | ❌ | ❌ | ✅ |
| **Peer blocking** | ✅ | ❌ | ❌ | ✅ |
| **Fingerprint mirror** | ✅ | ❌ | ❌ | ✅ |


## ⚡ Performance

Benchmarked on a single core:

| Operation | Throughput | Notes |
|-----------|-----------|-------|
| ChannelData decode | **9.3M msg/sec** | Hot path - near-zero overhead |
| CRC32 (fingerprint) | **5.1M/sec** | Pre-computed table |
| STUN decode | **218K msg/sec** | Full attribute parsing |
| STUN encode (no auth) | **50K msg/sec** | Attribute encoding + CRC32 |
| STUN encode (SHA1) | **36K msg/sec** | HMAC-SHA1 is the bottleneck |
| HMAC-SHA1 | **314K/sec** | Node.js crypto (OpenSSL) limit |

The **data relay hot path** - which handles 99% of traffic - uses ChannelData (4-byte header, no STUN overhead, no HMAC). Control messages (allocate, refresh, permissions) use full STUN encoding with integrity, but these occur only a few times per minute.

Optimizations applied:
- Zero-copy ChannelData via `Uint8Array.subarray()`
- No FINGERPRINT on Data indications (hot path skip)
- O(1) channel↔peer reverse index
- Pre-computed CRC32 table at module load
- Chunk-accumulation TCP framing (no `Buffer.concat` per packet)


## 🧪 Interoperability Testing

### Our client → coturn server

```bash
# Start coturn
turnserver -a -u test:test -r example.com --no-tls --no-dtls
```

```js
import { connect } from 'turn-server';

connect('turn:127.0.0.1:3478', { username: 'test', password: 'test' }, (err, sock) => {
  sock.allocate();
  sock.on('allocate:success', (msg) => {
    console.log('Relay:', msg.getAttribute(0x0016)); // XOR-RELAYED-ADDRESS
  });
});
```

### coturn client → our server

```bash
turnutils_uclient -u test -w test 127.0.0.1
```

### Chrome/Firefox WebRTC → our server

```js
new RTCPeerConnection({
  iceServers: [{
    urls: 'turn:your-server.com:3478',
    username: 'alice',
    credential: 'password123'
  }]
});
```


## 📁 Project Structure

```
turn-server/
├── index.js               - Public API: connect, getPublicIP, detectNAT, resolve, IceAgent
└── src/
    ├── wire.js              - Binary protocol: 62 attributes, encode/decode, integrity, CRC32
    ├── session.js           - State machine: auth, allocations, permissions, channels, hooks
    ├── socket.js            - Transport: UDP/TCP/TLS client, relay socket, ChannelData routing
    ├── server.js            - Multi-endpoint listener, 5-tuple routing, convenience limits
    ├── ice_agent.js         - ICE agent (RFC 8445): gathering, checks, nomination, consent, restart
    └── ice_candidate.js     - Candidate primitives: priority, foundation, SDP parse/format (RFC 8839)
```

| File | Lines | Role |
|------|-------|------|
| `wire.js` | 1,203 | Binary protocol - every byte on the wire |
| `session.js` | 1,705 | Protocol logic - state machine, auth, hooks |
| `socket.js` | 959 | Network I/O - UDP, TCP, TLS, relay sockets |
| `server.js` | 1,275 | Server orchestration - listeners, routing, limits |
| `ice_agent.js` | 2,718 | ICE agent - gathering, pairing, checks, nomination, consent, restart |
| `ice_candidate.js` | 459 | Candidate primitives - priority, foundation, SDP parse/format |
| `index.js` | 234 | Client convenience - connect, DNS, NAT detection |
| **Total** | **~8,550** | **lemon-tls (DTLS) + ws (WebSocket server, optional)** |


## 🛣 Roadmap

### ✅ Done
- STUN (RFC 8489) - full protocol, all attributes, all auth mechanisms
- TURN (RFC 8656) - allocations, permissions, channels, relay
- TCP relay (RFC 6062) - CONNECT, CONNECTION_BIND
- NAT detection (RFC 5780) - CHANGE-REQUEST, OTHER-ADDRESS
- OAuth (RFC 7635) - token-based auth with event delegation
- ICE attributes (RFC 8445) - PRIORITY, USE-CANDIDATE, ICE-CONTROLLED/CONTROLLING
- **ICE agent (RFC 8445) - full + lite modes, trickle, gathering (host/srflx/relay), connectivity checks, regular nomination, peer-reflexive construction, role conflict resolution, ICE restart with seamless media continuity**
- **Consent Freshness (RFC 7675) - 15s interval with ±20% jitter, auto-transitions to disconnected/failed**
- **Candidate primitives (RFC 8839) - priority formula, foundation computation, SDP parse/format, mDNS**
- Multiplexing (RFC 7983) - STUN/TURN/DTLS demultiplexing
- RFC 5769 test vectors - 22/22 validated
- All 62 IANA-registered STUN attributes including vendor extensions
- 4 auth mechanisms: none, short-term, long-term, OAuth
- REST API credentials (shared secret)
- SHA1, SHA256, SHA384, SHA512 message integrity
- PASSWORD-ALGORITHMS negotiation + bid-down attack prevention
- USERHASH computation (RFC 8489 §14.4)
- Multi-endpoint server (UDP + TCP + TLS + WebSocket + DTLS)
- DTLS transport (RFC 7350) - STUN/TURN over DTLS via LemonTLS (client + server)
- WebSocket client transport - via the global WebSocket (Node 22+) or an injected implementation
- 15-hook API for full server control, async by default (per-packet relay hooks stay sync), with per-hook rejection codes and a fail-closed `hookTimeout`
- Built-in convenience limits (connections, quotas, bandwidth, permissions, channels)
- Client: connect(), getPublicIP(), detectNAT(), DNS SRV, URI parsing, auto-refresh
- UDP retransmission (Rc=7, Rm=16) + TCP timeout (Ti=39.5s)
- Peer address blocking (loopback, multicast, unspecified)
- Nonce bound to 5-tuple (replay prevention)
- Fingerprint mirroring (per-session)
- Origin consistency checking
- UDP idle timeout + graceful drain
- Statistics and health checks
- **Async `authenticate` hook - one contract (`cb(passwordOrKey)` / `cb(err, passwordOrKey)`, sync or async) for long-term + short-term**
- **`auth:failure` event + live `authFailures` counter (rate-limiting / fail2ban hooks)**
- **`maxConnections` + graceful drain enforced on every transport (UDP, TCP, TLS, WS, DTLS)**
- **EVEN-PORT / RESERVATION-TOKEN full flow (RFC 5766 §14.6/§14.9) - token in the Allocate response, cross-connection claim, 30s TTL**
- **ICMP error forwarding (RFC 8656 §11.5) - Data indication with ICMP attribute + client `icmp` event**
- **ICE restart re-announces candidates; re-gather binds only new interfaces and reuses TURN allocations**
- **mDNS candidates (draft-ietf-mmusic-mdns-ice-candidates) - inbound `.local` resolution with strict UUID validation + opt-in outbound concealment (`register`), via lazy optional `mdns-local`**
- **Port-mapping assisted gathering (UPnP-IGD / NAT-PMP / PCP) - gateway-forwarded srflx candidates with CGNAT detection and budgeted cancellation, via lazy optional `port-mapper`**
- **Per-allocation packet counters (`packetsIn` / `packetsOut`) exposed through `getBandwidth()`**
- 450+ tests passing (297 core + 153 ICE)

_Community contributions are welcome! Please ⭐ star the repo to follow progress._


## 🙏 Sponsors

**turn-server** is an independent open-source project.
Support development via **GitHub Sponsors** or simply share the project.


## 📜 License

**Apache License 2.0**

```
Copyright © 2025 colocohen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```