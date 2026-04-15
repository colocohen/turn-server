<h1 align="center">turn-server</h1>
<p align="center">
  <em>Production-grade STUN/TURN server and client for Node.js - zero dependencies</em>
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
5. [Hooks API](#-hooks-api)
6. [Client API](#-client-api)
7. [Comparison](#-comparison)
8. [Performance](#-performance)
9. [Interoperability Testing](#-interoperability-testing)
10. [Project Structure](#-project-structure)
11. [Roadmap](#-roadmap)
12. [Sponsors](#-sponsors)
13. [License](#-license)


## ⚡ What is STUN / TURN?

**STUN** (Session Traversal Utilities for NAT) and **TURN** (Traversal Using Relays around NAT) are the protocols that make real-time communication possible across the Internet. They are the foundation of **WebRTC** - every video call, screen share, and peer-to-peer connection relies on them.

The problem they solve:

- **NAT traversal**: Most devices sit behind NATs that block incoming connections. STUN lets a client discover its public IP and port. When direct connections fail, TURN relays traffic through a server.

- **Universal connectivity**: TURN guarantees that two peers can always communicate, even behind the most restrictive firewalls and symmetric NATs - by relaying through a server that both sides can reach.

- **ICE framework**: Interactive Connectivity Establishment (ICE) uses STUN and TURN together to find the best path between peers - direct if possible, relayed if necessary.

Every WebRTC application needs a STUN/TURN server. Google, Twilio, Cloudflare, and others operate massive TURN infrastructure. With **turn-server**, you can embed this capability directly into your Node.js application.


## 🧠 Why turn-server?

The existing options for STUN/TURN in Node.js are limited: **coturn** is a C daemon you run separately, **node-turn** is a minimal server with basic features, and the **stun** npm package only handles STUN (no TURN). None of them give you a complete, embeddable library with full protocol coverage.

**turn-server** is a from-scratch implementation of the complete STUN/TURN protocol stack - both client and server - built as a library you can `require()` into any Node.js application. It covers every RFC, every attribute, every edge case, with zero dependencies.

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
  { port: 5349, transport: 'tls', cert: CERT, key: KEY }, // TLS
]);
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


## ✨ Features

### Wire Protocol (RFC 8489 / 8656)
- 62 STUN/TURN attributes with full encode/decode - every IANA-registered type
- 11 methods: BINDING, ALLOCATE, REFRESH, SEND, DATA, CREATE_PERMISSION, CHANNEL_BIND, CONNECT, CONNECTION_BIND, CONNECTION_ATTEMPT, GOOG_PING
- MESSAGE-INTEGRITY (SHA1), MESSAGE-INTEGRITY-SHA256, SHA384, SHA512
- FINGERPRINT (CRC32 with XOR), timing-safe comparison
- ChannelData encode/decode (zero-copy subarray)
- TCP framing (2-byte length prefix)
- STUN/TURN URI parsing (RFC 7064 / 7065)
- SASLprep / NFKC normalization
- RFC 5769 test vectors - 22/22 passing

### Server
- Multi-endpoint: UDP, TCP, TLS, WebSocket on any combination of ports
- 4 auth mechanisms: none, short-term, long-term, OAuth (RFC 7635)
- REST API credentials (shared secret, time-limited)
- PASSWORD-ALGORITHMS negotiation with bid-down attack prevention
- Structured nonces bound to source address (replay prevention)
- Fingerprint mirroring - server mirrors client's FINGERPRINT usage per-session
- SNICallback for multi-domain TLS (like `node:tls`)
- realmCallback for per-client realm/auth configuration
- relayCallback for per-allocation relay address selection
- EVEN-PORT and RESERVATION-TOKEN support
- TCP relay (RFC 6062) - CONNECT and CONNECTION_BIND
- NAT behavior discovery (RFC 5780) - CHANGE-REQUEST with secondary address
- Peer address blocking - loopback, multicast, unspecified blocked by default (CVE-2020-26262)
- Origin consistency checking

### Server - Production Features
- Built-in convenience limits: `maxConnections`, `userQuota`, `totalQuota`, `maxDataSize`, `maxPermissionsPerAllocation`, `maxChannelsPerAllocation`
- UDP idle timeout - automatically removes dead 5-tuple entries (default 5 min)
- Graceful shutdown - `drain(timeout, cb)` stops new connections, waits for existing
- Statistics - `getStats()` returns 7 real-time counters
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


## 🪝 Hooks API

Every decision point in the server is exposed as a hook. Hooks receive an info object and a callback - `cb(true)` to allow, `cb(false)` to deny. If no listener is attached, the action is auto-approved.

```js
server.on('accept', (info, cb) => {
  // info: { source: { ip, port }, transport: 'udp'|'tcp'|'tls' }
  cb(isAllowed(info.source.ip));
});

server.on('authenticate', (username, realm, cb) => {
  // Return HMAC key from database
  db.getKey(username, realm).then(key => cb(key));
});

server.on('beforeAllocate', (info, cb) => {
  // info: { username, source, transport, lifetime }
  // Modify lifetime: info.lifetime = 300;
  cb(true);
});

server.on('beforeRelay', (info, cb) => {
  // info: { username, source, peer, size, direction: 'inbound'|'outbound' }
  cb(info.size < 65535);  // drop oversized packets
});
```

All 14 hooks:

| Hook | When | Info |
|------|------|------|
| `accept` | New connection | source, transport |
| `authenticate` | Long-term auth | username, realm → cb(hmacKey) |
| `authenticate_oauth` | OAuth auth | token, realm → cb(err, key) |
| `authorize` | After auth | username, method |
| `quota` | Before allocate | username → cb(allowed) |
| `beforeAllocate` | Allocate request | username, transport, lifetime |
| `beforeRefresh` | Refresh request | username, lifetime |
| `beforePermission` | Permission request | username, peer |
| `beforeChannelBind` | Channel bind | username, channel, peer |
| `beforeConnect` | TCP connect (6062) | username, peer |
| `beforeRelay` | Data relay (out) | username, peer, size |
| `beforeData` | Data relay (in) | peer, size |
| `onRelayed` | After relay | direction, peer, size |
| `redirect` | Client got 300 | server, domain |

Hooks and built-in limits work together - built-in checks run first, then your hook is called. Set a limit to `0` (default) to disable the built-in check and handle it entirely in your hook.


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
| **Dependencies** | **0** | 0 | 5+ | OpenSSL, DB |
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
| **DTLS** | planned | ❌ | ❌ | ✅ |
| | | | | |
| **Client connect()** | ✅ | ❌ | ✅ | ✅ uclient |
| **getPublicIP()** | ✅ | ❌ | ✅ | ❌ |
| **NAT detection** | ✅ | ❌ | ❌ | ❌ |
| **DNS SRV** | ✅ | ❌ | ❌ | ❌ |
| **Auto-refresh** | ✅ | ❌ | ❌ | ✅ |
| | | | | |
| **Hooks API** | ✅ 14 hooks | ❌ | ❌ | ❌ |
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
├── index.js               - Public API: connect, getPublicIP, detectNAT, resolve
└── src/
    ├── wire.js              - Binary protocol: 62 attributes, encode/decode, integrity, CRC32
    ├── session.js           - State machine: auth, allocations, permissions, channels, hooks
    ├── socket.js            - Transport: UDP/TCP/TLS client, relay socket, ChannelData routing
    └── server.js            - Multi-endpoint listener, 5-tuple routing, convenience limits
```

| File | Lines | Role |
|------|-------|------|
| `wire.js` | 1,059 | Binary protocol - every byte on the wire |
| `session.js` | 1,586 | Protocol logic - state machine, auth, hooks |
| `socket.js` | 658 | Network I/O - UDP, TCP, TLS, relay sockets |
| `server.js` | 731 | Server orchestration - listeners, routing, limits |
| `index.js` | 203 | Client convenience - connect, DNS, NAT detection |
| **Total** | **4,237** | **Zero dependencies** |


## 🛣 Roadmap

### ✅ Done
- STUN (RFC 8489) - full protocol, all attributes, all auth mechanisms
- TURN (RFC 8656) - allocations, permissions, channels, relay
- TCP relay (RFC 6062) - CONNECT, CONNECTION_BIND
- NAT detection (RFC 5780) - CHANGE-REQUEST, OTHER-ADDRESS
- OAuth (RFC 7635) - token-based auth with event delegation
- ICE attributes (RFC 8445) - PRIORITY, USE-CANDIDATE, ICE-CONTROLLED/CONTROLLING
- Multiplexing (RFC 7983) - STUN/TURN/DTLS demultiplexing
- RFC 5769 test vectors - 22/22 validated
- All 62 IANA-registered STUN attributes including vendor extensions
- 4 auth mechanisms: none, short-term, long-term, OAuth
- REST API credentials (shared secret)
- SHA1, SHA256, SHA384, SHA512 message integrity
- PASSWORD-ALGORITHMS negotiation + bid-down attack prevention
- USERHASH computation (RFC 8489 §14.4)
- Multi-endpoint server (UDP + TCP + TLS + WebSocket)
- 14-hook API for full server control
- Built-in convenience limits (connections, quotas, bandwidth, permissions, channels)
- Client: connect(), getPublicIP(), detectNAT(), DNS SRV, URI parsing, auto-refresh
- UDP retransmission (Rc=7, Rm=16) + TCP timeout (Ti=39.5s)
- Peer address blocking (loopback, multicast, unspecified)
- Nonce bound to 5-tuple (replay prevention)
- Fingerprint mirroring (per-session)
- Origin consistency checking
- UDP idle timeout + graceful drain
- Statistics and health checks
- 297 tests passing

### ⏳ Planned
- DTLS transport (pending LemonTLS DTLS support)
- WebSocket client transport
- TypeScript type definitions (`.d.ts`)
- `npm publish`

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
