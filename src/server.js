import dgram from 'node:dgram';
import net from 'node:net';
import crypto from 'node:crypto';
import os from 'node:os';
// lemon-tls is this library's TLS: for the TLS listener and for DTLS. One
// implementation throughout — the same certificate contexts (an SNICallback
// hands back a lemon-tls context), the same behaviour. node:tls is not used;
// a context from a lemon-tls SNICallback could not be used with it at all.
import lemonTls from 'lemon-tls';
import fs from 'node:fs';
import { EventEmitter } from 'node:events';

import Socket from './socket.js';
import { makeNonce } from './session.js';
import * as wire from './wire.js';
import { compilePeerRanges } from './peer_policy.js';


// Resolve createDTLSServer: an injected implementation if one was passed,
// otherwise lemon-tls's. cb(err, createDTLSServer), always asynchronously.
function resolveCreateDTLSServer(config, ctx, cb) {
  var fn = config.createDTLSServer
        || (config.lemonTls && config.lemonTls.createDTLSServer)
        || ctx.createDTLSServer
        || (ctx.lemonTls && ctx.lemonTls.createDTLSServer);
  if (typeof fn !== 'function') fn = lemonTls.createDTLSServer;
  queueMicrotask(function () {
    if (typeof fn !== 'function') return cb(new Error("lemon-tls has no createDTLSServer export"));
    cb(null, fn);
  });
}

// Load a PEM cert/key that may be a path, a string, or a Buffer.
function loadPem(v) {
  if (v == null) return v;
  if (Buffer.isBuffer(v)) return v;
  if (typeof v === 'string' && v.indexOf('-----') < 0) return fs.readFileSync(v);
  return v;
}

// Resolve the DTLSSession constructor (for shared-socket DTLS, where
// turn-server drives the datagrams instead of letting lemon-tls own a socket):
// an injected one if passed, otherwise lemon-tls's. cb(err, DTLSSession).
function resolveDTLSSession(cfg, ctx, cb) {
  var fn = (cfg && cfg.DTLSSession)
        || (cfg && cfg.lemonTls && cfg.lemonTls.DTLSSession)
        || (ctx.lemonTls && ctx.lemonTls.DTLSSession);
  if (typeof fn !== 'function') fn = lemonTls.DTLSSession;
  queueMicrotask(function () {
    if (typeof fn !== 'function') return cb(new Error("lemon-tls has no DTLSSession export"));
    cb(null, fn);
  });
}

// Bytes queued on a TCP/TLS client connection past which relayed data is
// dropped instead of queued (see setup_stream_connection). ~0.25 s of 8 Mbit/s.
var STREAM_RELAY_HIGH_WATER = 256 * 1024;

function Server(options) {
  if (!(this instanceof Server)) return new Server(options);
  options = options || {};

  var ev = new EventEmitter();
  var self = this;

  var listen_config = options.listen || [];
  var relay_config = options.relay || {};
  var auth_config = options.auth || {};

  var context = {
    // One nonce key for every client of this server (Session nonceKey).
    nonceKey: crypto.randomBytes(16),
    software: options.software || null,

    // Relay config
    relayIp: relay_config.ip || '0.0.0.0',
    externalIp: relay_config.externalIp || null,
    portRange: relay_config.portRange || [49152, 65535],
    relayLocal: checkRelayLocal(relay_config.local, 'createServer'),

    // Auth config
    authMech: auth_config.mechanism || 'none',
    realm: auth_config.realm || null,
    credentials: auth_config.credentials || {},
    secret: auth_config.secret || null,

    // Callbacks
    sniCallback: options.sniCallback || options.SNICallback || null,
    realmCallback: options.realmCallback || null,
    relayCallback: options.relayCallback || null,

    // Server-level TLS/DTLS material, inherited by every 'tls' and 'dtls'
    // endpoint that doesn't override it. e.g. createServer({ tls: { cert, key,
    // ca, SNICallback } }). Endpoint-level config in listen() still wins.
    tlsDefaults: options.tls || null,

    // Shared-socket DTLS (RFC 7350 over the external socket). When external
    // socket mode is active AND this is set, handlePacket() demuxes DTLS
    // records (RFC 7983 first-byte 20–63) into per-peer DTLSSessions instead
    // of treating them as cleartext STUN. cert/key fall back to tlsDefaults.
    dtlsShared:        options.dtls || null,
    _DTLSSessionCtor:  null,   // resolved lemon-tls DTLSSession constructor
    _dtlsCtorErr:      null,
    dtlsConns:         {},      // 5-tuple key → { session, client, idle }

    // DTLS implementation (lemon-tls). Optional injection so non-DTLS users
    // need no dependency; falls back to lemon-tls's own at listen time.
    createDTLSServer: options.createDTLSServer || null,
    lemonTls: options.lemonTls || null,

    // Allocation limits
    maxAllocateLifetime: options.maxAllocateLifetime || 3600,
    defaultAllocateLifetime: options.defaultAllocateLifetime || 600,

    // Security
    secureStun: !!options.secureStun,
    checkOriginConsistency: !!options.checkOriginConsistency,
    allowLoopback: !!options.allowLoopback,
    allowMulticast: !!options.allowMulticast,
    // Private, link-local, CGNAT and ULA peers (192.168/16, 10/8, 169.254/16,
    // 100.64/10, fc00::/7, …) are refused by default — the relay would
    // otherwise be a way into the network the server sits in. See peer_policy.js.
    allowPrivatePeers: !!options.allowPrivatePeers,
    allowedPeers: options.allowedPeers || null,   // CIDR list — coturn allowed-peer-ip
    deniedPeers: options.deniedPeers || null,     // CIDR list — coturn denied-peer-ip
    // RFC 6062 TCP allocations (Connect). Off unless asked for.
    allowTcpRelay: !!options.allowTcpRelay,
    maxTcpConnectionsPerAllocation: options.maxTcpConnectionsPerAllocation || 8,

    // ── Built-in convenience limits (zero/null = unlimited) ──
    maxConnections: options.maxConnections || 0,
    userQuota: options.userQuota || 0,          // max allocations per username
    totalQuota: options.totalQuota || 0,         // max allocations globally
    ipQuota: options.ipQuota || 0,               // max allocations per client IP
    maxDataSize: options.maxDataSize || 0,       // max DATA attribute size in bytes
    // Default caps, as coturn has (1024 permissions): with no cap, one client
    // could grow an allocation's tables without bound. 0 = unlimited.
    maxPermissionsPerAllocation: options.maxPermissionsPerAllocation != null ? options.maxPermissionsPerAllocation : 1024,
    maxChannelsPerAllocation: options.maxChannelsPerAllocation != null ? options.maxChannelsPerAllocation : 1024,

    // UDP idle timeout — remove 5-tuple entry after N ms of no traffic (default 5 min)
    idleTimeout: options.idleTimeout !== undefined ? options.idleTimeout : 300000,

    // A client that has no allocation is cheap to create and costs a slot of
    // maxConnections all the same — a forged-source UDP flood, or idle TCP
    // connections, would fill the table and lock real clients out. Such a
    // client is dropped after this much quiet (ms). With an allocation, the
    // allocation's own lifetime decides instead. 0 = use idleTimeout.
    unallocatedTimeout: options.unallocatedTimeout !== undefined ? options.unallocatedTimeout : 30000,

    // TLS listener: a connection must finish its handshake within this (ms).
    // Before it does, it counts against maxConnections like any other.
    handshakeTimeout: options.handshakeTimeout || 10000,
    pendingHandshakes: 0,

    // Budget for a hook that defers its decision (DB/Redis lookup). A hook that
    // never calls cb would otherwise pin the connection forever, so the
    // decision falls back to deny once this elapses. Also passed to each
    // client Socket → Session so every hook shares one budget.
    hookTimeout: options.hookTimeout || 5000,

    // 5-tuples with an accept hook still pending. Further datagrams from the
    // same 5-tuple are dropped while it sits here rather than queued: the
    // client's STUN retransmission will re-deliver once the decision lands,
    // and queuing would let a spoofed source grow our heap for free.
    pendingAccepts: {},

    // Graceful shutdown
    draining: false,

    // Statistics
    stats: {
      totalConnections: 0,
      activeConnections: 0,
      totalAllocations: 0,
      activeAllocations: 0,
      authFailures: 0,
      packetsRelayed: 0,
      bytesRelayed: 0,
    },

    // Per-user allocation tracking (for userQuota)
    _userAllocations: Object.create(null),   // keyed by client-chosen usernames: no prototype
    // Per-IP allocation tracking (for ipQuota)
    _ipAllocations: Object.create(null),

    // RFC 5766 §14.9 — port reservations (EVEN-PORT R bit → RESERVATION-TOKEN).
    // Server-scoped and shared with every client Socket, because the token is
    // claimed by a NEW allocation arriving on a DIFFERENT 5-tuple.
    // tokenHex → { socket, timer }
    relayReservations: {},

    listeners: [],
    clients: {},
    destroyed: false,

    // ── External socket mode (shared UDP port) ──
    // When set, Server does not create its own UDP socket. Instead, the user
    // feeds packets via server.handlePacket(msg, rinfo) and queries state
    // via server.hasClient(rinfo). See RFC 9443 for multiplexing scheme.
    externalSocket:     options.socket  || null,    // IPv4 dgram.Socket (pre-bound)
    externalSocket6:    options.socket6 || null,    // IPv6 dgram.Socket (pre-bound)
    externalLocalAddr:  null,                        // cached from socket.address()
    externalLocalAddr6: null,                        // cached from socket6.address()
  };

  // Fail fast on a broken auth config. Long-term (and REST-API) credentials
  // are derived as MD5(username:realm:password) and the realm is mandatory in
  // the 401 challenge — without it the challenge can't be built and every
  // client hangs in an auth loop. Catch this at construction time with a
  // clear message instead of failing silently per packet.
  // A typo in a peer range must fail here, not quietly allow everything.
  compilePeerRanges(context.allowedPeers);
  compilePeerRanges(context.deniedPeers);

  if (context.authMech === 'long-term' && !context.realm && !context.realmCallback) {
    throw new Error(
      "turn-server: auth.mechanism 'long-term' requires auth.realm (or a realmCallback). " +
      "The realm is sent in the 401 challenge and is part of key derivation: " +
      "key = MD5(username:realm:password).");
  }

  // Cache local addresses from external sockets. Sockets MUST be bound
  // before being passed to createServer — this is validated here so errors
  // surface immediately rather than on first packet.
  if (context.externalSocket) {
    try {
      var _a4 = context.externalSocket.address();
      context.externalLocalAddr = { ip: _a4.address, port: _a4.port };
    } catch (e) {
      throw new Error('options.socket must be bound before createServer()');
    }
  }
  if (context.externalSocket6) {
    try {
      var _a6 = context.externalSocket6.address();
      context.externalLocalAddr6 = { ip: _a6.address, port: _a6.port };
    } catch (e) {
      throw new Error('options.socket6 must be bound before createServer()');
    }
  }

  // Merge endpoint config with server-level tls defaults (endpoint wins).
  function tlsField(config, name) {
    if (config && config[name] != null) return config[name];
    if (context.tlsDefaults && context.tlsDefaults[name] != null) return context.tlsDefaults[name];
    return undefined;
  }

  // Preload the DTLSSession constructor for shared-socket DTLS so handlePacket()
  // (a hot, synchronous path) can use it without awaiting an import per packet.
  // Until it resolves, inbound DTLS records are dropped — harmless, since DTLS
  // retransmits its ClientHello.
  if ((context.externalSocket || context.externalSocket6) && context.dtlsShared) {
    resolveDTLSSession(context.dtlsShared, context, function(err, Ctor) {
      if (err) context._dtlsCtorErr = err;
      else context._DTLSSessionCtor = Ctor;
    });
  }


  /* ====================== 5-tuple key ====================== */

  function make_udp_key(src_ip, src_port, dst_ip, dst_port) {
    return 'udp:' + src_ip + ':' + src_port + ':' + dst_ip + ':' + dst_port;
  }

  // Source ports of the UDP 5-tuple keys present in context.clients or
  // context.dtlsConns — a pre-filter for hasClient(), which the demuxer calls
  // for a large share of all QUIC packets on a shared port. A packet whose
  // source port no UDP client uses cannot match, so hasClient answers false
  // without building the key string. Any other port goes on to the exact
  // check, as before. Maintained by udpKeySet / udpKeyDelete, the only writes
  // to UDP keys in those two maps.
  var udpPortRefs = new Map();            // src port → entries in the two maps
  var udpKeyPort = Object.create(null);   // udp key → its src port

  function udpKeySet(mapName, key, port, value) {
    var map = context[mapName];
    if (!map[key] && value) {
      udpPortRefs.set(port, (udpPortRefs.get(port) || 0) + 1);
      udpKeyPort[key] = port;
    }
    map[key] = value;
  }

  function udpKeyDelete(mapName, key) {
    var map = context[mapName];
    if (map[key] && (key in udpKeyPort)) {
      var port = udpKeyPort[key];
      var n = (udpPortRefs.get(port) || 0) - 1;
      if (n > 0) udpPortRefs.set(port, n); else udpPortRefs.delete(port);
    }
    delete map[key];
    if (!context.clients[key] && !context.dtlsConns[key]) delete udpKeyPort[key];
  }


  /* ====================== Socket factory ====================== */

  // cfg is what admit_client() resolved for this client — the realm and the
  // credentials to check it against. Resolved before this point, because
  // realmCallback may answer asynchronously and the Socket cannot exist until
  // it has. Absent (a caller outside the admission path), the server-wide
  // settings apply.
  function relayLocal(ip, port) {
    return context.relayLocal ? context.relayLocal(ip, port) : null;
  }

  // Is ip an address of this machine — the announced external IP, the relay
  // IP, an interface? RFC 8656 §21.1.7: a relay
  // must not be turned into a path back into the server — TURN over TURN, or
  // anything else forwarded to this machine (the WebRTC server on the shared
  // port), arriving from inside. Relays of our own are reached in memory
  // before this is asked (socket.js), so only the rest is refused.
  var _ifaceIps = null, _ifaceIpsAt = 0;
  function own_ips() {
    var now = Date.now();
    if (!_ifaceIps || now - _ifaceIpsAt > 30000) {
      _ifaceIps = {};
      var ifs = os.networkInterfaces();
      for (var n in ifs) for (var i = 0; i < ifs[n].length; i++) _ifaceIps[ifs[n][i].address] = true;
      _ifaceIpsAt = now;
    }
    return _ifaceIps;
  }
  function isSelfService(ip, port) {
    if (!ip) return false;
    // Any port: behind a home router the announced address is the router,
    // and whatever else it forwards (SSH, HTTP, a NAS) would be one relay away
    // and reached from inside. Peers that share this machine's address are
    // reached by their host or private candidates, not through our relay.
    return ip === context.externalIp || (context.relayIp && ip === context.relayIp) || !!own_ips()[ip];
  }

  // The relay settings as they are now — read by each client Socket at every
  // allocation, so setConfiguration({ relay }) applies to clients that exist.
  function relayConfig() {
    return { relayIp: context.relayIp, externalIp: context.externalIp, portRange: context.portRange };
  }

  // Entries of a permissions/channels map that have not expired; expired
  // ones are deleted on the way.
  // hold: how long after expiry an entry is kept (a channel number stays
  // reserved for 5 minutes, RFC 8656 §12).
  function live_count(map, expiryOf, hold) {
    var now = Date.now(), n = 0;
    for (var k in map) {
      var exp = expiryOf(map[k]);
      if (exp > now) n++;
      else if (exp + (hold || 0) <= now) delete map[k];
    }
    return n;
  }

  function create_client_socket(source, send_fn, localAddress, transport, cfg) {
    var realm       = cfg ? cfg.realm       : context.realm;
    var authMech    = cfg ? cfg.authMech    : context.authMech;
    var credentials = cfg ? cfg.credentials : context.credentials;
    var secret      = cfg ? cfg.secret      : context.secret;

    var sock = new Socket({
      isServer: true,
      source: source,
      send: send_fn,
      software: context.software,
      authMech: authMech,
      realm: realm,
      credentials: credentials,
      secret: secret,
      relayIp: context.relayIp,
      externalIp: context.externalIp,
      portRange: context.portRange,
      relayConfig: relayConfig,
      nonceKey: context.nonceKey,
      isSelfService: isSelfService,
      // Read at each send, so setConfiguration reaches allocations already open.
      relayLocal: relayLocal,
      relayCallback: context.relayCallback,
      reservations: context.relayReservations,
      maxAllocateLifetime: context.maxAllocateLifetime,
      defaultAllocateLifetime: context.defaultAllocateLifetime,
      secureStun: context.secureStun,
      checkOriginConsistency: context.checkOriginConsistency,
      allowLoopback: context.allowLoopback,
      allowMulticast: context.allowMulticast,
      allowPrivatePeers: context.allowPrivatePeers,
      allowedPeers: context.allowedPeers,
      deniedPeers: context.deniedPeers,
      allowTcpRelay: context.allowTcpRelay,
      maxTcpConnectionsPerAllocation: context.maxTcpConnectionsPerAllocation,
      localAddress: localAddress || null,
      transportType: transport || null,
      hookTimeout: context.hookTimeout,
    });

    // Forward hooks from Session → Server EventEmitter
    var session = sock.getSession();

    // Auth hooks (no built-in equivalent — always forward)
    session.on('authenticate', function(username, realm, cb) {
      if (ev.listenerCount('authenticate') > 0) ev.emit('authenticate', username, realm, cb);
      else cb(new Error('no handler'));
    });

    session.on('authorize', function(info, cb) {
      if (ev.listenerCount('authorize') > 0) ev.emit('authorize', info, cb);
      else cb(true);
    });

    session.on('beforeBindingResponse', function(info, cb) {
      if (ev.listenerCount('beforeBindingResponse') > 0) ev.emit('beforeBindingResponse', info, cb);
      else cb(true);
    });

    session.on('beforeRefresh', function(info, cb) {
      if (ev.listenerCount('beforeRefresh') > 0) ev.emit('beforeRefresh', info, cb);
      else cb(true);
    });

    session.on('beforeConnect', function(info, cb) {
      if (ev.listenerCount('beforeConnect') > 0) ev.emit('beforeConnect', info, cb);
      else cb(true);
    });

    // Socket-level hooks (no built-in equivalent)
    sock.on('beforeData', function(info, cb) {
      if (ev.listenerCount('beforeData') > 0) ev.emit('beforeData', info, cb);
      else cb(true);
    });

    sock.on('allocate', function(alloc) {
      context.stats.totalAllocations++;
      context.stats.activeAllocations++;
      // Track per-user for userQuota
      var u = alloc.username || '_anon';
      context._userAllocations[u] = (context._userAllocations[u] || 0) + 1;
      var sip = source && source.ip;
      if (sip) context._ipAllocations[sip] = (context._ipAllocations[sip] || 0) + 1;
      alloc._quotaIp = sip || null;
      ev.emit('allocate', sock, alloc);
    });

    sock.on('allocate:expired', function(alloc) {
      context.stats.activeAllocations--;
      var u = alloc.username || '_anon';
      if (context._userAllocations[u]) {
        context._userAllocations[u]--;
        // Delete at zero — with REST-style usernames ("timestamp:user") every
        // session has a UNIQUE username, so keeping zero-count keys would
        // grow this map forever (memory leak on a long-running server).
        if (context._userAllocations[u] <= 0) delete context._userAllocations[u];
      }
      var qip = alloc._quotaIp;
      if (qip && context._ipAllocations[qip]) {
        if (--context._ipAllocations[qip] <= 0) delete context._ipAllocations[qip];
      }
      ev.emit('allocate:expired', sock, alloc);
    });

    // A client's own trouble (a malformed message, a relay send that failed)
    // is not the server's: 'clientError', never 'error'.
    sock.on('error', function(err) {
      client_error(err, transport, source);
    });

    // Stats: count real authentication failures (bad integrity, unknown user,
    // wrong credentials — NOT the initial 401 challenge of the normal flow).
    // A peer the policy refused (403) — for logging / banning (see peer_policy.js).
    session.on('peer:blocked', function(info) {
      if (ev.listenerCount('peer:blocked') > 0) ev.emit('peer:blocked', info);
    });

    session.on('auth:failure', function(info) {
      context.stats.authFailures++;
      ev.emit('auth:failure', sock, info);
    });

    // Stats: relay tracking
    sock.on('onRelayed', function(info) {
      context.stats.packetsRelayed++;
      context.stats.bytesRelayed += info.size || 0;
      ev.emit('onRelayed', sock, info);
    });

    // Built-in convenience limits — enforced via internal hooks on Session
    var sess = sock.getSession();

    // userQuota / ipQuota / totalQuota — read at each check, so a
    // setConfiguration() change applies to clients already connected (it used
    // to be fixed by whichever branch was taken when the client connected).
    sess.on('quota', function(username, cb) {
      if (context.userQuota > 0 && (context._userAllocations[username || '_anon'] || 0) >= context.userQuota) {
        cb(false, 486); return;   // Allocation Quota Reached
      }
      if (ev.listenerCount('quota') > 0) ev.emit('quota', username, cb);
      else cb(true);
    });

    sess.on('beforeAllocate', function(info, cb) {
      if (context.totalQuota > 0 && context.stats.activeAllocations >= context.totalQuota) { cb(false, 486); return; }
      if (context.ipQuota > 0 && source && (context._ipAllocations[source.ip] || 0) >= context.ipQuota) { cb(false, 486); return; }
      if (ev.listenerCount('beforeAllocate') > 0) ev.emit('beforeAllocate', info, cb);
      else cb(true);
    });

    // maxDataSize: reject oversized relay data
    if (context.maxDataSize > 0) {
      sess.on('beforeRelay', function(info, cb) {
        if (info.size > context.maxDataSize) { cb(false); return; }
        if (ev.listenerCount('beforeRelay') > 0) ev.emit('beforeRelay', info, cb);
        else cb(true);
      });
    } else {
      sess.on('beforeRelay', function(info, cb) {
        if (ev.listenerCount('beforeRelay') > 0) ev.emit('beforeRelay', info, cb);
        else cb(true);
      });
    }

    // maxPermissionsPerAllocation / maxChannelsPerAllocation
    // The caps count what is live now. They used to count every key ever
    // added — expired entries are deleted only when looked up — and counted a
    // refresh of an existing permission as a new one, so a long call that had
    // seen 64 peer addresses (ICE restarts, a phone changing networks) had its
    // routine 5-minute permission refresh refused with 508, and went silent.
    sess.on('beforePermission', function(info, cb) {
      if (context.maxPermissionsPerAllocation > 0) {
        var alloc = sess.getAllocation();
        if (alloc) {
          // Everything this request would add, not just this peer: the peers
          // of one CreatePermission are all checked before any is installed,
          // so a per-peer check let one request with 50 peers past a cap of 4.
          var now = Date.now(), adds = {}, nAdd = 0;
          var list = (info && info.peers) || (info && info.peer ? [info.peer] : []);
          for (var pi = 0; pi < list.length; pi++) {
            var pip = list[pi] && list[pi].ip;
            if (pip && !(alloc.permissions[pip] > now) && !adds[pip]) { adds[pip] = true; nAdd++; }
          }
          if (nAdd > 0 && live_count(alloc.permissions, function(exp) { return exp; }) + nAdd > context.maxPermissionsPerAllocation) { cb(false, 508); return; }
        }
      }
      if (ev.listenerCount('beforePermission') > 0) ev.emit('beforePermission', info, cb);
      else cb(true);
    });

    sess.on('beforeChannelBind', function(info, cb) {
      if (context.maxChannelsPerAllocation > 0) {
        var alloc = sess.getAllocation();
        var cur = alloc && info && alloc.channels[info.channel];
        if (alloc && !(cur && cur.expiresAt > Date.now()) &&
            live_count(alloc.channels, function(ch) { return ch.expiresAt; }, 300000) >= context.maxChannelsPerAllocation) { cb(false, 508); return; }
      }
      if (ev.listenerCount('beforeChannelBind') > 0) ev.emit('beforeChannelBind', info, cb);
      else cb(true);
    });

    context.stats.totalConnections++;
    context.stats.activeConnections++;

    sock.on('close', function() {
      context.stats.activeConnections--;
    });

    ev.emit('connection', sock);

    return sock;
  }

  // Errors that belong to one client — a reset connection, a failed
  // handshake, a malformed message — go to 'clientError' (err, info). They
  // used to go to 'error', the event for the server's own listeners, so every
  // client that dropped its connection was logged as a server error.
  function client_error(err, transport, source) {
    if (ev.listenerCount('clientError') === 0) return;
    ev.emit('clientError', err, { transport: transport || null, source: source || null });
  }

  function has_allocation(client) {
    try { return !!(client && client.getAllocation && client.getAllocation()); } catch (e) { return false; }
  }

  // UDP idle timeout: reset timer on each feed, remove client on expiry.
  // Without an allocation the client gets unallocatedTimeout; with one, it is
  // kept for as long as the allocation lives (the allocation's lifetime is
  // what RFC 8656 uses for this), and dropped idleTimeout after it is gone.
  function setup_idle_timeout(key, ms) {
    var first = context.unallocatedTimeout || context.idleTimeout;
    if (!context.idleTimeout && !context.unallocatedTimeout) return null;
    var t = setTimeout(function() {
      var client = context.clients[key];
      if (!client) return;
      if (has_allocation(client)) {
        client._idleTimer = setup_idle_timeout(key, context.idleTimeout || first);
        return;
      }
      client.close();
      udpKeyDelete('clients', key);
    }, ms || first);
    if (t.unref) t.unref();
    return t;
  }

  // The same for a stream connection (TCP, TLS, WebSocket): closed after
  // unallocatedTimeout of quiet with no allocation. It had no timeout at all —
  // a connection that never sent a byte held its slot forever.
  function setup_stream_idle(conn, client) {
    var limit = context.unallocatedTimeout || context.idleTimeout;
    if (!limit) return function() {};
    var last = Date.now();
    var timer = null;
    function check() {
      timer = null;
      if (conn.destroyed) return;
      var quiet = Date.now() - last;
      if (has_allocation(client) || quiet < limit) {
        timer = setTimeout(check, has_allocation(client) ? limit : limit - quiet);
        if (timer.unref) timer.unref();
        return;
      }
      try { conn.destroy(); } catch (e) {}
    }
    timer = setTimeout(check, limit);
    if (timer.unref) timer.unref();
    conn.on('close', function() { if (timer) clearTimeout(timer); timer = null; });
    return function touch() { last = Date.now(); };
  }


  /* ====================== Hook helper ====================== */

  // Listener calls cb(allowed) synchronously or asynchronously; nothing
  // proceeds until it fires. No listener → auto-approve, with no allocation
  // and no trip through the event loop. A listener that never answers fails
  // closed once context.hookTimeout elapses.
  function check_hook(name, info, done) {
    if (ev.listenerCount(name) === 0) return done(true);

    var settled = false;
    var timer = null;

    function settle(allowed) {
      if (settled) return;
      settled = true;
      if (timer !== null) { clearTimeout(timer); timer = null; }
      done(!!allowed);
    }

    ev.emit(name, info, settle);

    if (!settled) {
      timer = setTimeout(function() { settle(false); }, context.hookTimeout);
      if (timer.unref) timer.unref();
    }
  }


  /* ====================== Admission ====================== */

  // Everything that decides whether — and as whom — a new client is served,
  // run before its Socket exists: the 'accept' hook, then realmCallback.
  // done(cfg) with the resolved per-client config, or done(null) to refuse.
  //
  // realmCallback used to be called inside create_client_socket and its
  // answer read on the very next line. A callback that answered
  // synchronously worked; one that answered later — after asking a database,
  // or another thread, which is the reason to have a callback at all — was
  // silently ignored, and the client got the server-wide realm instead of
  // its own. Every transport already waits here for the asynchronous
  // 'accept' decision, so resolving the realm in the same step adds no new
  // waiting, buffering or state.
  function admit_client(source, transport, done) {
    check_hook('accept', { source: source, transport: transport }, function(ok) {
      if (!ok) return done(null);
      resolve_client_config(source, transport, done);
    });
  }

  // realmCallback(info, cb) — info is { ip, port, transport }; cb takes:
  //   a string                                  → that realm
  //   { realm, mechanism, credentials, secret } → any of those overridden
  //   nothing (null / undefined)                → the server-wide settings
  //
  // Answered synchronously, the client is created in the same tick, as
  // before. Answered later, admission waits for it. Not answered within
  // hookTimeout, or throwing, the client is refused — failing closed, like
  // the other hooks: serving it under the default realm could check its
  // credentials against the wrong tenant's.
  function resolve_client_config(source, transport, done) {
    var cfg = {
      realm: context.realm,
      authMech: context.authMech,
      credentials: context.credentials,
      secret: context.secret,
    };
    if (!context.realmCallback) return done(cfg);

    var settled = false;
    var timer = null;

    function settle(result, failed) {
      if (settled) return;
      settled = true;
      if (timer !== null) { clearTimeout(timer); timer = null; }
      if (failed) return done(null);

      if (typeof result === 'string') {
        cfg.realm = result;
      } else if (result && typeof result === 'object') {
        if (result.realm) cfg.realm = result.realm;
        if (result.mechanism) cfg.authMech = result.mechanism;
        if (result.credentials) cfg.credentials = result.credentials;
        if (result.secret) cfg.secret = result.secret;
      }

      // Long-term credentials are keyed on the realm; without one there is
      // nothing to check a password against.
      if (cfg.authMech === 'long-term' && !cfg.realm) return done(null);
      done(cfg);
    }

    try {
      context.realmCallback({ ip: source.ip, port: source.port, transport: transport },
                            function(result) { settle(result, false); });
    } catch (e) {
      settle(null, true);
      ev.emit('error', e);
      return;
    }

    if (!settled) {
      timer = setTimeout(function() { settle(null, true); }, context.hookTimeout);
      if (timer.unref) timer.unref();
    }
  }


  /* ====================== UDP packet processing ====================== */

  // Shared between standalone start_udp() and external handlePacket().
  // send_fn signature: send_fn(buf, dst_port, dst_ip[, cb]) — cb, when given,
  // replaces the default error callback (lets a client reuse one).
  // Answer a Binding request with no state kept. Only a plain one: if it
  // carries any comprehension-required attribute (USERNAME of an ICE check,
  // say, or one this server does not know and must answer 420 for), false —
  // the caller takes the usual path. The 'accept' and beforeBindingResponse
  // hooks still decide.
  function stateless_binding(msg, src, local_addr, send_fn) {
    var req;
    try { req = wire.decode_message(new Uint8Array(msg.buffer, msg.byteOffset, msg.length)); } catch (e) { return true; }
    if (!req || req.cls !== wire.CLASS.REQUEST || req.method !== wire.METHOD.BINDING) return true;
    for (var i = 0; i < req.attributes.length; i++) {
      if (req.attributes[i].type < 0x8000) return false;
    }
    if (!wire.check_fingerprint(req.raw, req)) return true;   // silently dropped, as Session does
    check_hook('accept', { source: src, transport: 'udp' }, function(ok) {
      if (!ok || context.destroyed) return;
      check_hook('beforeBindingResponse', { source: src, transport: 'udp' }, function(ok2) {
        if (!ok2 || context.destroyed) return;
        // XOR-MAPPED-ADDRESS only (and SOFTWARE if configured): the answer to
        // an unauthenticated datagram is kept small — it is what a reflection
        // attack would get out of us.
        var attrs = [{ type: wire.ATTR.XOR_MAPPED_ADDRESS, value: src }];
        if (context.software) attrs.push({ type: wire.ATTR.SOFTWARE, value: context.software });
        var out = wire.encode_message({ method: wire.METHOD.BINDING, cls: wire.CLASS.SUCCESS,
          transactionId: req.transactionId, attributes: attrs, fingerprint: true });
        send_fn(wire.to_buffer(out.buf), src.port, src.ip, function(err) {
          if (err) client_error(err, 'udp', src);
        });
      });
    });
    return true;
  }

  // true when the datagram was taken here (answered or dropped).
  function stateless_challenge(msg, src, send_fn) {
    if (context.authMech !== 'long-term' && !context.realmCallback) return false;
    var req;
    try { req = wire.decode_message(new Uint8Array(msg.buffer, msg.byteOffset, msg.length)); } catch (e) { return false; }
    if (!req || req.cls !== wire.CLASS.REQUEST || req.method === wire.METHOD.BINDING) return false;
    if (req.integrity_offset !== null || req.integrity_sha256_offset !== null) return false;   // authenticated: the usual path
    for (var i = 0; i < req.attributes.length; i++) {
      var t = req.attributes[i].type;
      if (t < 0x8000 && !(t in wire.attrs)) return false;   // 420 is the Session's to send
    }
    if (!wire.check_fingerprint(req.raw, req)) return true;
    admit_client(src, 'udp', function(cfg) {
      if (!cfg || context.destroyed || context.draining) return;
      if (cfg.authMech !== 'long-term' || !cfg.realm) return;
      var attrs = [
        { type: wire.ATTR.ERROR_CODE, value: { code: 401 } },
        { type: wire.ATTR.REALM, value: cfg.realm },
        { type: wire.ATTR.NONCE, value: makeNonce(context.nonceKey, src.ip + ':' + src.port) },
        { type: wire.ATTR.PASSWORD_ALGORITHMS, value: [{ algorithm: 0x0001, params: new Uint8Array(0) }] },
      ];
      if (context.software) attrs.push({ type: wire.ATTR.SOFTWARE, value: context.software });
      var out = wire.encode_message({ method: req.method, cls: wire.CLASS.ERROR,
        transactionId: req.transactionId, attributes: attrs, fingerprint: true });
      send_fn(wire.to_buffer(out.buf), src.port, src.ip, function(err) {
        if (err) client_error(err, 'udp', src);
      });
    });
    return true;
  }

  function process_udp_packet(msg, rinfo, send_fn, local_addr) {
    if (context.destroyed) return;
    if (!local_addr) return;

    var key = make_udp_key(rinfo.address, rinfo.port, local_addr.ip, local_addr.port);

    var client = context.clients[key];
    if (!client) {
      var src = { ip: rinfo.address, port: rinfo.port };
      // Reject new connections when draining
      if (context.draining) return;
      // Only a STUN request opens a client. Anything else from an unknown
      // 5-tuple — ChannelData, an indication, noise, a forged flood — would
      // otherwise cost a client object and a maxConnections slot for nothing.
      if (msg.length < 20 || !wire.is_stun(msg) || (msg[0] & 0x01) !== 0 || (msg[1] & 0x10) !== 0 ||
          msg[4] !== 0x21 || msg[5] !== 0x12 || msg[6] !== 0xA4 || msg[7] !== 0x42) return;
      // A plain Binding request (address discovery, what a browser sends to a
      // stun: URL) from an unknown 5-tuple is answered without creating a
      // client. Every such datagram used to get a full client (~21 KB) kept
      // for unallocatedTimeout, so a flood of them from forged addresses held
      // gigabytes; capping it with maxConnections locked real clients out
      // instead. coturn answers them statelessly too.
      if (msg[0] === 0x00 && msg[1] === 0x01 && !context.secureStun && stateless_binding(msg, src, local_addr, send_fn)) return;
      // Likewise the first, unauthenticated request of a TURN client (its
      // Allocate without credentials): answered with the 401 challenge, no
      // client kept. The nonce is bound to the source and signed with the
      // server's key, so the client created when the authenticated request
      // arrives accepts it. Spoofed floods no longer cost a client each.
      if (stateless_challenge(msg, src, send_fn)) return;
      // Built-in maxConnections check
      if (context.maxConnections > 0 && context.stats.activeConnections >= context.maxConnections) return;
      // A decision for this 5-tuple is already in flight — drop, don't queue.
      if (context.pendingAccepts[key]) return;

      // Capture rinfo values in closure — locked to this 5-tuple client.
      var dst_port = rinfo.port;
      var dst_ip   = rinfo.address;

      context.pendingAccepts[key] = true;

      // Admission: accept hook, then realm. Packets arriving meanwhile are
      // dropped (pendingAccepts, above) — STUN over UDP retransmits.
      admit_client(src, 'udp', function(cfg) {
        delete context.pendingAccepts[key];
        if (!cfg) return;
        // State can move underneath a deferred hook: the server may have been
        // destroyed or put into drain, or another packet may have won the race.
        if (context.destroyed || context.draining) return;
        if (context.clients[key]) return;

        // One send-error callback per client, not a new closure per datagram.
        var sendErr = function(err) {
          if (err) client_error(err, 'udp', { ip: dst_ip, port: dst_port });
        };
        var c = create_client_socket(src, function(buf) {
          // HOT PATH: zero-copy Buffer view. buf is Uint8Array from
          // wire.encode_message — Buffer.from(u.buffer, offset, len) creates
          // a view over the same memory rather than copying ~1200 bytes.
          var out = wire.to_buffer(buf);
          send_fn(out, dst_port, dst_ip, sendErr);
        }, local_addr, 'udp', cfg);

        udpKeySet('clients', key, dst_port, c);
        c._idleTimer = setup_idle_timeout(key);
        c._idleKey = key;

        c.on('close', function() {
          if (c._idleTimer) clearTimeout(c._idleTimer);
          udpKeyDelete('clients', key);
        });

        c.feed(msg);
      });

      return;
    }

    if (client._idleTimer) {
      // Refresh idle timer without re-allocating the timer object.
      // timer.refresh() is available since Node 10 — re-arms the existing
      // handle, saving a syscall pair per packet.
      if (typeof client._idleTimer.refresh === 'function') {
        client._idleTimer.refresh();
      } else {
        clearTimeout(client._idleTimer);
        client._idleTimer = setup_idle_timeout(client._idleKey);
      }
    }

    // HOT PATH: msg is Buffer. wire's r_bytes and validate_integrity now
    // handle Buffer input safely (see src/wire.js), so no wrapping needed.
    client.feed(msg);
  }


  /* ====================== UDP listener ====================== */

  function start_udp(config) {
    var port = config.port || 3478;
    var address = config.address || '0.0.0.0';
    var family = address.indexOf(':') >= 0 ? 'udp6' : 'udp4';

    // reuseAddr is OPT-IN. With reuseAddr:true, binding a port that this
    // process (or another) already holds SUCCEEDS silently — producing two
    // live listeners with separate client tables that split traffic
    // unpredictably. That failure mode is far worse than a loud EADDRINUSE,
    // so the default is false; pass { reuseAddr: true } per endpoint if you
    // genuinely need SO_REUSEADDR semantics.
    var udp = dgram.createSocket({ type: family, reuseAddr: config.reuseAddr === true });

    // Cached local address — udp.address() is a syscall. Safe to cache
    // after 'listening' fires, the address cannot change.
    var udp_local_addr = null;

    // send function closed over the bound socket
    var send_fn = function(out, dst_port, dst_ip, cb) {
      udp.send(out, 0, out.length, dst_port, dst_ip, cb || function(err) {
        if (err) client_error(err, 'udp', { ip: dst_ip, port: dst_port });
      });
    };

    udp.on('message', function(msg, rinfo) {
      process_udp_packet(msg, rinfo, send_fn, udp_local_addr);
    });

    udp.on('error', function(err) {
      // Annotate so consumers can react per-endpoint (e.g. re-listen only
      // the port that failed with EADDRINUSE).
      err.transport = 'udp'; err.port = port; err.address = address;
      ev.emit('error', err);
    });

    udp.on('listening', function() {
      var addr = udp.address();
      udp_local_addr = { ip: addr.address, port: addr.port };
      ev.emit('listening', { transport: 'udp', address: addr.address, port: addr.port });
    });

    udp.bind({ address: address, port: port, exclusive: true });

    context.listeners.push({ type: 'udp', socket: udp });
  }


  /* ====================== Stream connections (TCP, TLS) ====================== */

  // A dual-stack listener reports an IPv4 peer as ::ffff:a.b.c.d. That form
  // is unwrapped before it is used anywhere: it becomes the client's
  // XOR-MAPPED-ADDRESS, and encoded as IPv6 it tells an IPv4 client the wrong
  // thing about itself. It is also part of the 5-tuple key and the nonce
  // binding, where the same client must not appear under two spellings.
  function unmapIPv4(ip) {
    return (ip && ip.indexOf('::ffff:') === 0 && net.isIPv4(ip.substring(7))) ? ip.substring(7) : ip;
  }

  // Everything a new stream connection goes through, whichever door it came
  // in by: this server's own TCP or TLS listener, or handleTcpConnection()
  // from a caller that owns the port.
  //
  // It used to be written out twice, once inside each listener, identical but
  // for the transport label — and a connection handed in from outside could
  // reach neither copy.
  // Who is on the other end of a stream, and which local address it reached:
  // from `info` when the caller that owns the socket says (a TLS stack that
  // hands over its decrypted stream may not expose them itself), else from
  // the socket, else from the transport socket underneath it.
  function stream_addresses(conn, info) {
    info = info || {};
    var under = conn.socket || conn._parent || conn._socket || null;
    function pick(name) {
      if (info[name] != null) return info[name];
      if (conn[name] != null) return conn[name];
      return under && under[name] != null ? under[name] : null;
    }
    return {
      remote: { ip: unmapIPv4(pick('remoteAddress')), port: pick('remotePort') },
      local:  { ip: unmapIPv4(pick('localAddress')),  port: pick('localPort') },
    };
  }

  function accept_stream_connection(conn, transport, info) {
    if (context.destroyed) { conn.destroy(); return; }
    // Reject new connections while draining (graceful shutdown)
    if (context.draining) { conn.destroy(); return; }
    // Built-in maxConnections check (same policy as the UDP path)
    if (context.maxConnections > 0 && context.stats.activeConnections >= context.maxConnections) {
      conn.destroy();
      return;
    }

    // Nagle off (TCP_NODELAY), on every stream connection whichever door it
    // came in by — this server's TCP and TLS listeners, or a socket handed in.
    // Each relayed datagram is written as one small message; with Nagle on,
    // one written while the last is still unacknowledged waits for the ACK —
    // up to a round trip of added delay on real-time media, arriving in
    // bursts. coturn sets it for the same reason. A TLS socket passes it down
    // to its TCP socket.
    if (typeof conn.setNoDelay === 'function') conn.setNoDelay(true);

    var addrs = stream_addresses(conn, info);
    var src = addrs.remote;
    // No source address: a socket already reset (Node clears remoteAddress),
    // or a stream from a TLS stack that does not expose it. Every response
    // carries XOR-MAPPED-ADDRESS of the source, and encoding an undefined
    // address threw — once the Allocate succeeded, outside any try/catch, it
    // took the process down. Such a client cannot be served: refuse it.
    if (!src.ip || !net.isIP(src.ip) || !(src.port > 0)) {
      client_error(new Error('stream connection without a source address'), transport, src);
      try { conn.destroy(); } catch (e) {}
      return;
    }

    // Hook: accept. Nothing is read off the socket until the decision lands —
    // the stream stays paused (no 'data' listener yet) so the kernel and the
    // stream's own high-water mark apply backpressure instead of our heap.
    //
    // A socket handed in from outside arrives paused already, with any bytes
    // its owner read put back; the same pause/resume brackets it, and the
    // owner must leave the resume to this function.
    //
    // An error listener from this moment on. Paused or not, the socket is
    // still read from the kernel, so a reset while admission is pending (the
    // hook may answer asynchronously) surfaces as 'error' — and an 'error'
    // with no listener is an uncaught exception that takes the whole process
    // or worker down. A socket handed in arrives with its owner's listener
    // already removed. setup_stream_connection() puts the lasting one on; a
    // refused connection keeps this one until it is gone.
    function onEarlyError(err) { client_error(err, transport, src); }
    conn.on('error', onEarlyError);
    conn.pause();
    admit_client(src, transport, function(cfg) {
      if (!cfg || context.destroyed || context.draining) {
        conn.destroy();
        return;
      }
      if (conn.destroyed) return; // peer hung up while admission was pending

      conn.removeListener('error', onEarlyError);
      setup_stream_connection(conn, src, transport, cfg, addrs.local);
      conn.resume();
    });
  }

  // ChannelData (first byte 0x40–0x4F) or a Data indication (type 0x0017).
  function is_relayed_data(buf) {
    var b0 = buf[0];
    return (b0 >= 0x40 && b0 <= 0x4F) || (b0 === 0x00 && buf[1] === 0x17);
  }

  function setup_stream_connection(conn, src, transport, cfg, local) {
    var tcp_buf = Buffer.alloc(0);

    var client = create_client_socket(src, function(buf) {
      // HOT PATH: zero-copy Buffer view when buf is Uint8Array.
      // TCP stream.write() accepts both Buffer and Uint8Array natively,
      // but internally optimizes for Buffer.
      if (conn.destroyed) return;
      // Backpressure. Relayed media (ChannelData, Data indications) arrives
      // from peers over UDP at whatever rate they send; a TCP/TLS client that
      // cannot keep up used to have it queued in memory without limit — the
      // queue grew, and every packet waited behind seconds of older ones. Past
      // the high-water mark relayed data is dropped, as UDP would have dropped
      // it; STUN responses are always written.
      if (conn.writableLength > STREAM_RELAY_HIGH_WATER && is_relayed_data(buf)) {
        context.stats.relayDropped = (context.stats.relayDropped || 0) + 1;
        return;
      }
      // A byte stream: ChannelData must be padded to 4 (RFC 8656 §12.5).
      var out = wire.to_buffer(wire.pad_channel_data_for_stream(buf));
      conn.write(out);
    }, local || { ip: unmapIPv4(conn.localAddress), port: conn.localPort }, transport, cfg);

    // Store by connection reference
    // The local end too: one source ip:port may reach two of our listeners of
    // the same transport (TCP 3478 and TCP 443, TLS 5349 and TLS 443), and
    // keyed without it the second shadowed the first — stop(), addUser and
    // removeUser then missed that client.
    var lp = (local && local.port) || conn.localPort || 0;
    var key = transport + ':' + src.ip + ':' + src.port + ':' + lp;
    context.clients[key] = client;

    var touch = setup_stream_idle(conn, client);

    conn.on('data', function(chunk) {
      touch();
      tcp_buf = tcp_buf.length ? Buffer.concat([tcp_buf, chunk]) : chunk;

      // RFC 8489 §6.2.2: STUN over TCP is self-delimiting (no length prefix).
      while (tcp_buf.length >= 4) {
        var msg_len = wire.stun_stream_frame_length(tcp_buf, 0, tcp_buf.length);
        // Not STUN and not ChannelData: the stream is out of step, and
        // nothing after this point can be trusted to line up. It used to
        // resync one byte at a time — a client sending junk kept the server
        // scanning it forever. Close instead.
        if (msg_len === -1) { client_error(new Error('bad STUN framing'), transport, src); conn.destroy(); return; }
        if (msg_len === 0 || tcp_buf.length < msg_len) break;          // wait for more data

        var frame = tcp_buf.slice(0, msg_len);
        tcp_buf = tcp_buf.slice(msg_len);
        // HOT PATH: frame is a Buffer. wire handles both Buffer and
        // Uint8Array safely (see r_bytes/validate_integrity in wire.js).
        client.feed(frame);
      }
    });

    conn.on('error', function(err) { client_error(err, transport, src); });

    conn.on('close', function() {
      client.close();
      if (context.clients[key] === client) delete context.clients[key];
    });
  }

  // handleTcpConnection: TURN over TCP on a socket accepted elsewhere.
  //
  // The TCP counterpart of handlePacket() and handleWebSocket(): for a caller
  // that owns the port — typically to share it, telling HTTPS from STUN by the
  // first byte the client sends. The socket is treated exactly as one this
  // server's TCP listener accepted: same draining and maxConnections checks,
  // same 'accept' hook, same framing.
  //
  // Hand it over PAUSED, with any bytes already read put back
  // (socket.unshift), and do not resume it afterwards: resuming is decided by
  // the 'accept' hook, which may answer asynchronously. Resumed early, the
  // first STUN message would flow before anything is reading it, and be lost.
  // info (optional): { remoteAddress, remotePort, localAddress, localPort }
  // when the socket does not carry them itself.
  function handleTcpConnection(socket, info) {
    accept_stream_connection(socket, 'tcp', info);
  }

  // handleSecureConnection: TURN over TLS on a connection whose TLS someone
  // else already terminated — a server that shares its HTTPS port and tells
  // the two apart after the handshake (by ALPN 'stun.turn', or by the first
  // decrypted bytes when, as from a browser, there is no ALPN). `socket` is
  // the decrypted stream. Same contract as handleTcpConnection: handed over
  // paused, with any bytes already read put back, and resumed here.
  function handleSecureConnection(socket, info) {
    accept_stream_connection(socket, 'tls', info);
  }


  // Who a stream connection is, for an SNICallback that wants to know: the
  // fields of quico's tcp_listener connectionInfo, so one callback serves both.
  // An IPv4 client on a dual-stack socket arrives as ::ffff:a.b.c.d; reported
  // as the IPv4 address and family the client actually used.
  function connectionInfo(sock) {
    var local = unmapIPv4(sock.localAddress || null);
    return {
      transport: 'tls',
      localAddress: local,
      localPort: sock.localPort || null,
      family: local && net.isIPv6(local) ? 'IPv6' : 'IPv4',
      remoteAddress: unmapIPv4(sock.remoteAddress || null),
      remotePort: sock.remotePort || null,
    };
  }


  /* ====================== TCP listener ====================== */

  function start_tcp(config) {
    var port = config.port || 3478;
    var address = config.address || '0.0.0.0';

    var tcp = net.createServer(function(conn) {
      accept_stream_connection(conn, 'tcp');
    });

    tcp.on('error', function(err) {
      err.transport = 'tcp'; err.port = port; err.address = address;
      ev.emit('error', err);
    });

    tcp.on('listening', function() {
      var addr = tcp.address();
      ev.emit('listening', { transport: 'tcp', address: addr.address, port: addr.port });
    });

    tcp.listen(port, address);

    context.listeners.push({ type: 'tcp', socket: tcp });
  }


  /* ====================== TLS listener ====================== */

  function start_tls(config) {
    var port = config.port || 5349;
    var address = config.address || '0.0.0.0';

    // SNI: per-listener callback takes priority, then server-level tls default,
    // then the top-level sniCallback option.
    var sniCallback = tlsField(config, 'SNICallback') || tlsField(config, 'sniCallback')
                   || config.sniCallback || context.sniCallback || null;

    // Load cert/key/ca (endpoint config, falling back to server-level tls defaults)
    var _cert = loadPem(tlsField(config, 'cert'));
    var _key  = loadPem(tlsField(config, 'key'));
    var _ca   = loadPem(tlsField(config, 'ca'));

    // lemon-tls resolves a server certificate through its SNI path, so a fixed
    // key/cert is wrapped in a callback that returns one context, built once.
    var fixedCtx = (_cert && _key)
      ? lemonTls.createSecureContext({ cert: _cert, key: _key, ca: _ca || undefined })
      : null;

    var socketOptions = {
      isServer: true,
      SNICallback: sniCallback || (fixedCtx ? function (name, cb) { cb(null, fixedCtx); } : undefined),
      // RFC 7443 — ALPN protocol identifiers for STUN/TURN
      ALPNProtocols: config.ALPNProtocols || ['stun.turn', 'stun.nat-discovery'],
    };
    if (_ca) socketOptions.ca = _ca;

    // A plain net.Server with a lemon-tls TLSSocket per connection — the same
    // shape as quico's tcp_listener. Not lemon-tls's own Server: that one does
    // not re-emit 'listening' and 'error' from the net.Server inside it, so the
    // 'listening' below would never fire and an EADDRINUSE would be emitted
    // where nothing listens — an uncaught exception, and the process down.
    var tls_server = net.createServer(function (raw) {
      var secure = null, settled = false;

      // Connections still in their handshake are not yet in activeConnections,
      // and had no deadline: a client that opened the TCP connection and never
      // sent a ClientHello held a socket (and a file descriptor) forever, with
      // no maxConnections to stop the next ten thousand. Now they count, and
      // they have handshakeTimeout to finish.
      if (context.destroyed || context.draining ||
          (context.maxConnections > 0 &&
           context.stats.activeConnections + context.pendingHandshakes >= context.maxConnections)) {
        raw.destroy();
        return;
      }
      context.pendingHandshakes++;
      var pending = true;
      function unpend() { if (pending) { pending = false; context.pendingHandshakes--; } }
      var hsTimer = setTimeout(function() {
        onHandshakeError(new Error('TLS handshake timeout'));
      }, context.handshakeTimeout);
      if (hsTimer.unref) hsTimer.unref();
      raw.on('close', function() { clearTimeout(hsTimer); unpend(); });

      // In place BEFORE the handshake can fail. A failure can arrive from a
      // callback long after the constructor returned (an SNI lookup that finds
      // no certificate), and an error with no listener takes the process down.
      function onHandshakeError(err) {
        clearTimeout(hsTimer);
        unpend();
        if (!settled) {
          settled = true;
          if (ev.listenerCount('tlsClientError') > 0) ev.emit('tlsClientError', err, raw);
          client_error(err, 'tls', { ip: unmapIPv4(raw.remoteAddress), port: raw.remotePort });
        }
        try { if (secure) secure.destroy(); } catch (e) {}
        try { raw.destroy(); } catch (e) {}
      }
      raw.on('error', onHandshakeError);

      // The connection's details as a third SNICallback argument — the same
      // contract as quico's tcp_listener. A client connecting to a bare IP
      // (turns:190.27.101.252:5349) sends no SNI, since RFC 6066 §3 forbids an
      // IP literal there; the callback then has only this to pick the IP's
      // certificate by. Without it, turns: by IP failed every time (Chrome:
      // 701), while by name it worked.
      var connOptions = socketOptions;
      if (sniCallback) {
        var info = connectionInfo(raw);
        connOptions = Object.assign({}, socketOptions, {
          SNICallback: function (servername, cb) { return sniCallback(servername, cb, info); },
        });
      }

      try {
        secure = new lemonTls.TLSSocket(raw, connOptions);
      } catch (err) {
        onHandshakeError(err);
        return;
      }
      secure.on('error', onHandshakeError);

      // 'secure', not 'secureConnect': lemon-tls emits secureConnect only for
      // sockets it connects itself, as Node does.
      secure.on('secure', function () {
        if (settled) return;
        settled = true;
        clearTimeout(hsTimer);
        unpend();
        accept_stream_connection(secure, 'tls', { remoteAddress: raw.remoteAddress, remotePort: raw.remotePort,
                                                  localAddress: raw.localAddress, localPort: raw.localPort });
      });
    });

    tls_server.on('error', function(err) {
      err.transport = 'tls'; err.port = port; err.address = address;
      ev.emit('error', err);
    });

    tls_server.on('listening', function() {
      var addr = tls_server.address();
      ev.emit('listening', { transport: 'tls', address: addr.address, port: addr.port });
    });

    tls_server.listen(port, address);

    context.listeners.push({ type: 'tls', socket: tls_server });
  }


  /* ====================== WebSocket transport ====================== */

  // handleWebSocket: accept a WebSocket connection from any WS library (ws, uWebSockets, etc.)
  // The developer brings their own WebSocket server, we handle TURN inside.
  // Usage: wsServer.on('connection', function(ws, req) { server.handleWebSocket(ws, req); });
  function handleWebSocket(ws, req) {
    if (context.destroyed) { try { ws.close(); } catch(e) {} return; }
    // Reject new connections while draining (graceful shutdown).
    if (context.draining) { try { ws.close(); } catch(e) {} return; }
    // Built-in maxConnections check (same policy as the UDP path)
    if (context.maxConnections > 0 && context.stats.activeConnections >= context.maxConnections) {
      try { ws.close(); } catch(e) {}
      return;
    }

    var src = { ip: '0.0.0.0', port: 0 };

    // Try to extract source from req (HTTP upgrade request) or ws
    if (req && req.socket) {
      src.ip = req.socket.remoteAddress || '0.0.0.0';
      src.port = req.socket.remotePort || 0;
    } else if (ws._socket) {
      src.ip = ws._socket.remoteAddress || '0.0.0.0';
      src.port = ws._socket.remotePort || 0;
    }

    // Hook: accept. A WebSocket carries STUN over a reliable transport, where
    // there is no per-request retransmission to re-deliver a dropped frame —
    // the client would simply stall until Ti (39.5s). So frames arriving while
    // the decision is pending are held, not dropped. The source cannot be
    // spoofed (the TCP handshake already completed), and the buffer is capped,
    // so this cannot be used to grow our heap. Any BYO WebSocket works: the
    // listener is attached immediately rather than relying on pause/resume.
    var ws_pending = [];
    var ws_client = null;
    var WS_PENDING_MAX = 32;

    ws.on('message', function(msg) {
      if (context.destroyed) return;
      // HOT PATH: msg is usually a Buffer from ws; if it's ArrayBuffer
      // (browser-style), wrap once — no way to avoid here.
      var data = msg instanceof ArrayBuffer ? new Uint8Array(msg) : msg;
      if (ws_client === null) {
        if (ws_pending !== null && ws_pending.length < WS_PENDING_MAX) ws_pending.push(data);
        return;
      }
      ws_client.feed(data);
    });

    admit_client(src, 'ws', function(cfg) {
      if (!cfg || context.destroyed || context.draining) {
        ws_pending = null;
        try { ws.close(); } catch(e) {}
        return;
      }
      setup_ws_connection(cfg);
    });

    function setup_ws_connection(cfg) {
    var client = create_client_socket(src, function(buf) {
      try {
        if (ws.readyState === 1) { // OPEN
          // HOT PATH: zero-copy Buffer view. ws library accepts both
          // Buffer and Uint8Array, but Buffer is the optimized path.
          var out = wire.to_buffer(buf);
          ws.send(out);
        }
      } catch(e) {}
    }, null, 'ws', cfg);

    var key = 'ws:' + src.ip + ':' + src.port + ':' + Date.now();
    context.clients[key] = client;

    ws.on('error', function(err) { client_error(err, 'ws', src); });

    ws.on('close', function() {
      client.close();
      delete context.clients[key];
    });

    // Route live frames to the session, then flush anything held during the hook.
    ws_client = client;
    var held = ws_pending;
    ws_pending = null;
    if (held) for (var i = 0; i < held.length; i++) client.feed(held[i]);
    }
  }


  /* ====================== WebSocket listener (optional auto-attach) ====================== */

  // start_ws bridges a WebSocket server into the TURN engine. turn-server does
  // not require a WS library for the common cases; resolution order is:
  //
  //   (a) a running WS server instance via `wsServer`
  //       (anything that emits 'connection' with (ws, req)), or
  //   (b) a WS server *constructor* via `WebSocketServer`
  //       (e.g. the `ws` package's `WebSocketServer`), instantiated on
  //       { port, host, path } (or { server } to attach to an http(s).Server), or
  //   (c) a lazy import('ws') fallback (install `ws`), or
  //   (d) a clear, actionable error.
  //
  // For Express/Fastify/HTTP apps, prefer calling server.handleWebSocket(ws, req)
  // yourself from your own upgrade handler — see the README.
  function start_ws(config) {
    if (config.wsServer) { wireWsServer(config, config.wsServer); return; }

    if (config.WebSocketServer) {
      var inst = instantiateWsServer(config, config.WebSocketServer);
      if (inst) wireWsServer(config, inst);
      return;
    }

    // Lazy import('ws') — only loaded when actually starting a ws listener.
    import('ws').then(function(m) {
      var Ctor = m.WebSocketServer || (m.default && m.default.Server) || m.Server;
      if (typeof Ctor !== 'function') {
        ev.emit('error', new Error("ws transport: installed 'ws' has no WebSocketServer export"));
        return;
      }
      var inst = instantiateWsServer(config, Ctor);
      if (inst) wireWsServer(config, inst);
    }).catch(function() {
      ev.emit('error', new Error(
        "ws transport requires the 'ws' package. Install it (npm i ws), pass a " +
        "'wsServer' instance or 'WebSocketServer' constructor in the listen config, " +
        "or call server.handleWebSocket(ws, req) from your own WebSocket server."));
    });
  }

  function instantiateWsServer(config, Ctor) {
    var ctorOpts = { port: config.port || 3478, host: config.address || '0.0.0.0' };
    if (config.path) ctorOpts.path = config.path;
    if (config.server) { delete ctorOpts.port; delete ctorOpts.host; ctorOpts.server = config.server; }
    try {
      return new Ctor(ctorOpts);
    } catch (e) {
      ev.emit('error', e);
      return null;
    }
  }

  function wireWsServer(config, wsServer) {
    wsServer.on('connection', function(ws, req) {
      handleWebSocket(ws, req);
    });

    wsServer.on('error', function(err) {
      err.transport = 'ws'; err.port = config.port || null;
      ev.emit('error', err);
    });

    if (typeof wsServer.on === 'function') {
      wsServer.on('listening', function() {
        ev.emit('listening', { transport: 'ws', address: config.address || '0.0.0.0', port: config.port || null });
      });
    }
    // Some WS servers attached to an existing http.Server never emit 'listening'
    // themselves — surface a listening event immediately in that case.
    if (config.wsServer || config.server) {
      ev.emit('listening', { transport: 'ws', address: config.address || '0.0.0.0', port: config.port || null });
    }

    // Tracked so stop()/drain() can close it (ws.WebSocketServer and http.Server
    // both expose .close(cb)).
    context.listeners.push({ type: 'ws', socket: wsServer });
  }


  /* ====================== DTLS listener (RFC 7350) ====================== */

  // STUN/TURN over DTLS. lemon-tls's createDTLSServer owns its own UDP socket
  // and per-peer demux, handing us a connected DTLSSocket per client — so this
  // bridges almost exactly like handleWebSocket: one DTLSSocket <-> one TURN
  // client Socket. DTLS preserves datagram boundaries, so there is no framing
  // (each 'data' is one STUN/ChannelData message), and the relay path to peers
  // stays plain UDP as usual.
  function start_dtls(config) {
    var port = config.port || 5349;
    var address = config.address || '0.0.0.0';

    resolveCreateDTLSServer(config, context, function(err, createDTLSServer) {
      if (err) { ev.emit('error', err); return; }

      var cert = loadPem(tlsField(config, 'cert'));
      var key  = loadPem(tlsField(config, 'key'));
      if (!cert || !key) {
        ev.emit('error', new Error('dtls transport requires cert and key (in the listen config or createServer({ tls }))'));
        return;
      }

      var dtlsServer;
      try {
        dtlsServer = createDTLSServer({
          cert: cert,
          key: key,
          ca: loadPem(tlsField(config, 'ca')),
          requestCert: config.requestCert,
          SNICallback: tlsField(config, 'SNICallback') || tlsField(config, 'sniCallback')
                    || config.sniCallback || context.sniCallback || undefined,
          alpnProtocols: config.alpnProtocols || ['stun.turn', 'stun.nat-discovery'],
          minVersion: config.minVersion || 'DTLSv1.2',
          maxVersion: config.maxVersion || 'DTLSv1.3',
          mtu: config.mtu,
          // DoS mitigation: require a HelloVerifyRequest cookie round-trip by
          // default for an internet-facing relay (override with useCookies:false).
          useCookies: config.useCookies !== false,
        });
      } catch (e) { ev.emit('error', e); return; }

      var localAddr = { ip: address, port: port };

      dtlsServer.on('connection', function(dsock) {
        if (context.destroyed) { try { dsock.close(); } catch (e) {} return; }
        if (context.draining)  { try { dsock.close(); } catch (e) {} return; }
        // Built-in maxConnections check (same policy as the UDP path)
        if (context.maxConnections > 0 && context.stats.activeConnections >= context.maxConnections) {
          try { dsock.close(); } catch (e) {}
          return;
        }

        var src = { ip: dsock.remoteAddress, port: dsock.remotePort };

        // Hook: accept. The DTLS handshake (and its HelloVerifyRequest cookie)
        // has already completed here, so the source is verified and records
        // arriving during the decision are held rather than dropped — DTLS does
        // not retransmit application data, only handshake flights.
        var d_pending = [];
        var d_client = null;
        var D_PENDING_MAX = 32;

        dsock.on('data', function(d) {
          if (context.destroyed) return;
          var data = (d instanceof ArrayBuffer) ? new Uint8Array(d) : d;
          if (d_client === null) {
            if (d_pending !== null && d_pending.length < D_PENDING_MAX) d_pending.push(data);
            return;
          }
          d_client.feed(data);
        });

        admit_client(src, 'dtls', function(cfg) {
          if (!cfg || context.destroyed || context.draining) {
            d_pending = null;
            try { dsock.close(); } catch (e) {}
            return;
          }
          setup_dtls_connection(cfg);
        });

        function setup_dtls_connection(cfg) {
        var client = create_client_socket(src, function(buf) {
          // One STUN/ChannelData message per DTLS datagram (no framing).
          try {
            var out = wire.to_buffer(buf);
            dsock.send(out);
          } catch (e) {}
        }, localAddr, 'dtls', cfg);

        var key2 = 'dtls:' + src.ip + ':' + src.port;
        context.clients[key2] = client;

        dsock.on('error', function(e) { client_error(e, 'dtls', src); });

        dsock.on('close', function() {
          client.close();
          delete context.clients[key2];
        });

        // Route live records to the session, then flush anything held.
        d_client = client;
        var held = d_pending;
        d_pending = null;
        if (held) for (var i = 0; i < held.length; i++) client.feed(held[i]);
        }
      });

      dtlsServer.on('clientError', function(e) { client_error(e, 'dtls', null); });
      dtlsServer.on('error', function(e) {
        e.transport = 'dtls'; e.port = port; e.address = address;
        ev.emit('error', e);
      });

      dtlsServer.listen(port, address, function() {
        ev.emit('listening', { transport: 'dtls', address: address, port: port });
      });

      // dtlsServer exposes .close(cb) — trackable for stop()/drain().
      context.listeners.push({ type: 'dtls', socket: dtlsServer });
    });
  }


  /* ====================== start / stop ====================== */

  function startConfigs(configs) {
    for (var i = 0; i < configs.length; i++) {
      var lc = configs[i];
      var transport = (lc.transport || 'udp').toLowerCase();

      if (transport === 'udp') {
        start_udp(lc);
      } else if (transport === 'tcp') {
        start_tcp(lc);
      } else if (transport === 'tls') {
        start_tls(lc);
      } else if (transport === 'ws' || transport === 'wss') {
        start_ws(lc);
      } else if (transport === 'dtls') {
        start_dtls(lc);
      } else {
        ev.emit('error', new Error('Unknown transport: ' + transport));
      }
    }
  }

  function start() {
    startConfigs(listen_config);
  }

  // listen() — like Node's server.listen(). Accepts config and starts.
  // Usage:
  //   server.listen({ port: 3478 })
  //   server.listen({ port: 3478, transport: 'udp' })
  //   server.listen([{ port: 3478 }, { port: 5349, transport: 'tls', cert, key }])
  //
  // Each call starts ONLY the endpoints it adds. (Starting the accumulated
  // listen_config on every call silently double-bound earlier UDP ports —
  // reuseAddr allowed two listeners with separate client tables on the same
  // port, splitting traffic unpredictably.)
  function listen(config, cb) {
    if (!config) config = [{ port: 3478, transport: 'udp' }];
    if (!Array.isArray(config)) config = [config];

    var added = [];

    // Each item: if only port specified, start both UDP and TCP on it
    for (var i = 0; i < config.length; i++) {
      var lc = config[i];
      if (!lc.transport) {
        // Default: start UDP + TCP on same port
        var u = Object.assign({}, lc, { transport: 'udp' });
        var t = Object.assign({}, lc, { transport: 'tcp' });
        listen_config.push(u, t);
        added.push(u, t);
      } else {
        listen_config.push(lc);
        added.push(lc);
      }
    }

    startConfigs(added);
    if (cb) cb();
  }

  // Graceful drain: stop accepting new connections, wait for existing to finish
  function drain(timeout, cb) {
    if (typeof timeout === 'function') { cb = timeout; timeout = 30000; }
    context.draining = true;

    // Check periodically if all clients are gone
    var drainInterval = setInterval(function() {
      if (Object.keys(context.clients).length === 0) {
        clearInterval(drainInterval);
        clearTimeout(drainTimer);
        stop(cb);
      }
    }, 500);

    // Force stop after timeout
    var drainTimer = setTimeout(function() {
      clearInterval(drainInterval);
      stop(cb);
    }, timeout);
  }

  function stop(cb) {
    context.destroyed = true;
    context.draining = false;

    var keys = Object.keys(context.clients);
    for (var i = 0; i < keys.length; i++) {
      try { context.clients[keys[i]].close(); } catch (e) {}
    }
    context.clients = {};
    udpPortRefs.clear();

    // Close any shared-socket DTLS sessions (and their idle timers).
    var dkeys = Object.keys(context.dtlsConns);
    for (var d = 0; d < dkeys.length; d++) {
      var de = context.dtlsConns[dkeys[d]];
      if (de && de.idle) { try { clearTimeout(de.idle); } catch (e) {} }
      if (de && de.session) { try { de.session.close(); } catch (e) {} }
    }
    context.dtlsConns = {};
    udpPortRefs.clear();
    udpKeyPort = Object.create(null);

    // Release unclaimed port reservations (RFC 5766 §14.9).
    var rvkeys = Object.keys(context.relayReservations);
    for (var rv = 0; rv < rvkeys.length; rv++) {
      var rentry = context.relayReservations[rvkeys[rv]];
      if (rentry && rentry.timer) { try { clearTimeout(rentry.timer); } catch (e) {} }
      if (rentry && rentry.socket) { try { rentry.socket.close(); } catch (e) {} }
    }
    context.relayReservations = {};

    var pending = context.listeners.length;
    if (pending === 0) {
      ev.emit('close');
      if (cb) cb();
      return;
    }

    for (var j = 0; j < context.listeners.length; j++) {
      try { context.listeners[j].socket.close(done); }
      catch (e) { done(); }
    }

    function done() {
      pending--;
      if (pending <= 0) {
        context.listeners = [];
        ev.emit('close');
        if (cb) cb();
      }
    }
  }


  /* ====================== Credential management ====================== */

  function addUser(username, password) {
    context.credentials[username] = password;
    // Update existing client sessions
    var keys = Object.keys(context.clients);
    for (var i = 0; i < keys.length; i++) {
      context.clients[keys[i]].addUser(username, password);
    }
  }

  function removeUser(username) {
    delete context.credentials[username];
    var keys = Object.keys(context.clients);
    for (var i = 0; i < keys.length; i++) {
      context.clients[keys[i]].removeUser(username);
    }
  }


  /* ====================== External socket API ====================== */

  // Feed an incoming UDP packet from an externally-managed socket.
  // rinfo must be in Node's dgram format: { address, port, family, size }.
  // Called by the demuxer when a packet is identified as TURN traffic.
  function handlePacket(msg, rinfo) {
    if (context.destroyed) return;

    // Select the right socket + local address based on packet's family
    var isV6 = rinfo.family === 'IPv6';
    var sock      = isV6 ? context.externalSocket6    : context.externalSocket;
    var localAddr = isV6 ? context.externalLocalAddr6 : context.externalLocalAddr;

    if (!sock || !localAddr) return;  // external mode not configured for this family

    // RFC 7983 demux: a DTLS record's first byte is 20–63. When shared-socket
    // DTLS is enabled, route those into per-peer DTLSSessions (RFC 7350 over
    // the shared port) instead of parsing them as cleartext STUN.
    if (context.dtlsShared && msg && msg.length > 0 && msg[0] >= 20 && msg[0] <= 63) {
      handleDtlsPacket(msg, rinfo, sock, localAddr);
      return;
    }

    process_udp_packet(msg, rinfo, externalSendFn(sock, isV6), localAddr);
  }

  // One send_fn per external socket (per family), not one per datagram.
  // Rebuilt when the socket is replaced.
  function externalSendFn(sock, isV6) {
    var slot = isV6 ? '_externalSend6' : '_externalSend';
    var cached = context[slot];
    if (cached && cached.sock === sock) return cached.fn;
    var fn = function(out, dst_port, dst_ip, cb) {
      sock.send(out, 0, out.length, dst_port, dst_ip, cb || function(err) {
        if (err) client_error(err, 'udp', { ip: dst_ip, port: dst_port });
      });
    };
    context[slot] = { sock: sock, fn: fn };
    return fn;
  }


  /* ── Shared-socket DTLS (RFC 7350 over the external UDP socket) ── */

  function handleDtlsPacket(msg, rinfo, sock, localAddr) {
    if (!context._DTLSSessionCtor) {
      // Constructor not ready: surface a load error once, otherwise drop and
      // let DTLS retransmit its ClientHello.
      if (context._dtlsCtorErr && !context._dtlsCtorReported) {
        context._dtlsCtorReported = true;
        ev.emit('error', context._dtlsCtorErr);
      }
      return;
    }

    var key = make_udp_key(rinfo.address, rinfo.port, localAddr.ip, localAddr.port);
    var entry = context.dtlsConns[key];

    if (!entry) {
      if (context.draining) return;
      if (context.maxConnections > 0 && context.stats.activeConnections >= context.maxConnections) return;
      // A decision for this 5-tuple is already in flight — drop, don't queue.
      // Unlike the dedicated-port DTLS listener, this hook fires on the first
      // datagram, before any handshake, so the source is still spoofable and
      // buffering would be a free way to grow our heap. DTLS retransmits its
      // ClientHello, so the client recovers once the decision lands.
      if (context.pendingAccepts[key]) return;
      context.pendingAccepts[key] = true;

      // Admission here, on the first datagram, as the accept hook always was
      // on this path — the realm is resolved along with it, and carried to
      // the handshake's end, where the client is created.
      admit_client({ ip: rinfo.address, port: rinfo.port }, 'dtls', function(cfg) {
        delete context.pendingAccepts[key];
        if (!cfg) return;
        if (context.destroyed || context.draining) return;
        if (context.dtlsConns[key]) return; // another datagram won the race

        var e2 = createDtlsConn(key, rinfo, sock, localAddr, cfg);
        if (!e2) return;
        if (e2.idle && typeof e2.idle.refresh === 'function') e2.idle.refresh();
        e2.session.feedDatagram(msg);
      });

      return;
    }

    if (entry.idle && typeof entry.idle.refresh === 'function') entry.idle.refresh();
    entry.session.feedDatagram(msg);
  }

  // cfg: the admission config (realm, auth mechanism, credentials) the
  // 'accept' hook and realmCallback resolved for this client. It used to be
  // shadowed by the DTLS settings below (`var cfg = context.dtlsShared`), so
  // the TURN client was created with no authMech at all — shared-socket DTLS
  // clients were served without authentication.
  function createDtlsConn(key, rinfo, sock, localAddr, cfg) {
    var dcfg = context.dtlsShared || {};
    var cert = loadPem(dcfg.cert != null ? dcfg.cert : (context.tlsDefaults && context.tlsDefaults.cert));
    var keyPem = loadPem(dcfg.key != null ? dcfg.key : (context.tlsDefaults && context.tlsDefaults.key));
    if (!cert || !keyPem) {
      ev.emit('error', new Error('shared-socket DTLS requires cert and key (in createServer({ dtls }) or createServer({ tls }))'));
      return null;
    }

    var session;
    try {
      session = new context._DTLSSessionCtor({
        isServer: true,
        cert: cert,
        key: keyPem,
        ca: loadPem(dcfg.ca != null ? dcfg.ca : (context.tlsDefaults && context.tlsDefaults.ca)),
        requestCert: dcfg.requestCert,
        SNICallback: dcfg.SNICallback || (context.tlsDefaults && context.tlsDefaults.SNICallback) || context.sniCallback || undefined,
        alpnProtocols: dcfg.alpnProtocols || ['stun.turn', 'stun.nat-discovery'],
        minVersion: dcfg.minVersion || 'DTLSv1.2',
        maxVersion: dcfg.maxVersion || 'DTLSv1.3',
        mtu: dcfg.mtu,
        useCookies: dcfg.useCookies !== false,
      });
    } catch (e) { ev.emit('error', e); return null; }

    var entry = { session: session, client: null, idle: null };
    udpKeySet('dtlsConns', key, rinfo.port, entry);

    var dst_ip = rinfo.address, dst_port = rinfo.port;

    function cleanup() {
      if (entry.idle) { clearTimeout(entry.idle); entry.idle = null; }
      if (entry.client) { try { entry.client.close(); } catch (e) {} }
      udpKeyDelete('clients', key);
      udpKeyDelete('dtlsConns', key);
    }

    // Idle reaper (reuses the UDP idleTimeout). Refreshed on each inbound record.
    if (context.idleTimeout) {
      entry.idle = setTimeout(function() { try { session.close(); } catch (e) {} cleanup(); }, context.idleTimeout);
      if (entry.idle.unref) entry.idle.unref();
    }

    // DTLS → wire: send encrypted records back over the shared socket.
    session.on('packet', function(data) {
      if (context.destroyed) return;
      var out = wire.to_buffer(data);
      sock.send(out, 0, out.length, dst_port, dst_ip, function(err) { if (err) client_error(err, 'dtls', { ip: dst_ip, port: dst_port }); });
    });

    // Handshake complete → build the TURN client Socket. Outbound TURN bytes
    // are encrypted via session.send(); decrypted inbound arrives on 'data'.
    session.on('connect', function() {
      if (entry.client || context.destroyed) return;
      var client = create_client_socket({ ip: dst_ip, port: dst_port }, function(buf) {
        try { session.send(buf); } catch (e) {}
      }, localAddr, 'dtls', cfg);
      entry.client = client;
      udpKeySet('clients', key, dst_port, client);
      client.on('close', function() { udpKeyDelete('clients', key); });
    });

    session.on('data', function(plain) {
      if (!entry.client || context.destroyed) return;
      entry.client.feed(plain instanceof ArrayBuffer ? new Uint8Array(plain) : plain);
    });

    session.on('error', function(e) { client_error(e, 'dtls', { ip: dst_ip, port: dst_port }); });
    session.on('close', cleanup);

    return entry;
  }

  // Query whether the given 5-tuple matches an active TURN client.
  // Used by the demuxer to disambiguate byte 0 in range 64-79 between
  // TURN ChannelData and QUIC short header (RFC 9443).
  function hasClient(rinfo) {
    if (context.destroyed) return false;

    var isV6 = rinfo.family === 'IPv6';
    var localAddr = isV6 ? context.externalLocalAddr6 : context.externalLocalAddr;
    if (!localAddr) return false;

    // No UDP client from this source port → no match; skip building the key.
    if (!udpPortRefs.has(rinfo.port)) return false;

    var key = make_udp_key(rinfo.address, rinfo.port, localAddr.ip, localAddr.port);
    return !!context.clients[key] || !!context.dtlsConns[key];
  }


  /* ====================== API ====================== */

  var api = {
    context: context,

    on:  function(name, fn) { ev.on(name, fn); },
    off: function(name, fn) { ev.off(name, fn); },

    start: start,
    listen: listen,
    stop: stop,

    addUser: addUser,
    removeUser: removeUser,

    /** Get number of connected clients */
    getClientCount: function() { return Object.keys(context.clients).length; },

    /** Get all client sockets */
    getClients: function() { return context.clients; },

    /** Accept a WebSocket connection (from any WS library).
     *  Usage: wsServer.on('connection', (ws, req) => server.handleWebSocket(ws, req));
     */
    handleWebSocket: handleWebSocket,
    handleTcpConnection: handleTcpConnection,
    handleSecureConnection: handleSecureConnection,

    /** Graceful shutdown: stop new connections, wait for existing, then stop */
    drain: drain,

    /** Get server statistics */
    getStats: function() { return Object.assign({}, context.stats); },

    /** Health check */
    isHealthy: function() { return !context.destroyed && context.listeners.length > 0; },

    /** Check if server is draining */
    isDraining: function() { return context.draining; },

    /** Feed an incoming UDP packet from a shared/external socket.
     *  rinfo must be in Node's dgram format: { address, port, family, size }.
     *  See RFC 9443 for the demuxing scheme on shared UDP ports. */
    handlePacket: handlePacket,

    /** Returns true if the given 5-tuple is an active TURN client.
     *  Used by demuxers to disambiguate TURN ChannelData (byte 0: 64-79)
     *  from QUIC short header packets (also 64-127). */
    hasClient: hasClient,

    /** The server's current settings, in the shape createServer takes.
     *
     *  Named after RTCPeerConnection.getConfiguration(). Secrets are left out
     *  (auth.secret, auth.credentials) — this is for reading and adjusting
     *  settings, not a way to get credentials back out — as are callbacks and
     *  listen addresses, which describe the running server rather than
     *  settings of it. Everything returned can be passed back to
     *  setConfiguration unchanged. */
    getConfiguration: function() {
      return {
        software: context.software,
        relay: {
          ip: context.relayIp,
          externalIp: context.externalIp,
          portRange: [context.portRange[0], context.portRange[1]],
        },
        auth: {
          mechanism: context.authMech,
          realm: context.realm,
        },
        maxAllocateLifetime: context.maxAllocateLifetime,
        defaultAllocateLifetime: context.defaultAllocateLifetime,
        secureStun: context.secureStun,
        checkOriginConsistency: context.checkOriginConsistency,
        allowLoopback: context.allowLoopback,
        allowMulticast: context.allowMulticast,
        allowPrivatePeers: context.allowPrivatePeers,
        allowedPeers: context.allowedPeers ? [].concat(context.allowedPeers) : null,
        deniedPeers: context.deniedPeers ? [].concat(context.deniedPeers) : null,
        allowTcpRelay: context.allowTcpRelay,
        maxTcpConnectionsPerAllocation: context.maxTcpConnectionsPerAllocation,
        ipQuota: context.ipQuota,
        unallocatedTimeout: context.unallocatedTimeout,
        handshakeTimeout: context.handshakeTimeout,
        maxConnections: context.maxConnections,
        userQuota: context.userQuota,
        totalQuota: context.totalQuota,
        maxDataSize: context.maxDataSize,
        maxPermissionsPerAllocation: context.maxPermissionsPerAllocation,
        maxChannelsPerAllocation: context.maxChannelsPerAllocation,
        idleTimeout: context.idleTimeout,
        hookTimeout: context.hookTimeout,
      };
    },

    /** Change settings on a running server.
     *
     *    server.setConfiguration({ relay: { externalIp: '203.0.113.5' } });
     *
     *    var c = server.getConfiguration();
     *    c.maxConnections = 5000;
     *    server.setConfiguration(c);
     *
     *  Named after, and behaving like, RTCPeerConnection.setConfiguration():
     *
     *    - Partial: only the settings given are touched.
     *
     *    - A setting fixed at creation may be passed, as long as it is passed
     *      with its current value — which is what makes the get-modify-set
     *      round trip above work. Passing a different value throws
     *      InvalidModificationError, as the browser does for certificates or
     *      bundlePolicy. Nothing is accepted and silently ignored.
     *
     *    - A malformed value throws TypeError.
     *
     *    - All or nothing: every value is checked before any is applied, so a
     *      call that throws leaves the server exactly as it was.
     *
     *  What changes, and when it takes effect:
     *
     *    relay.externalIp, relay.ip, relay.portRange, maxAllocateLifetime,
     *    defaultAllocateLifetime, allowLoopback, allowMulticast, hookTimeout
     *        — read when a client connects: every client from now on. One
     *          already connected keeps what it was given, as a peer
     *          connection keeps its ICE servers until the next ICE restart.
     *
     *    maxConnections, userQuota, totalQuota, maxDataSize, idleTimeout,
     *    maxPermissionsPerAllocation, maxChannelsPerAllocation
     *        — read at each check: immediately, for everyone.
     *
     *    relay.local — read at each relayed datagram: immediately, for every
     *          allocation. A function, so never returned by getConfiguration;
     *          null removes it.
     *
     *  Fixed: software, auth.mechanism, auth.realm, secureStun,
     *  checkOriginConsistency — and, never returned by getConfiguration and
     *  so never part of a round trip: listen, tls, dtls, auth.secret,
     *  auth.credentials and the callbacks. */
    setConfiguration: function(changes) {
      if (!changes || typeof changes !== 'object') throw new TypeError('setConfiguration: expected an object');

      var apply = [];   // [contextKey, value] — applied only once all pass

      function fixed(name, current, v) {
        if (v === current) return;
        throw new DOMException('setConfiguration: ' + name + ' cannot change on a running server', 'InvalidModificationError');
      }
      function num(name, v) {
        if (typeof v !== 'number' || !isFinite(v) || v < 0) throw new TypeError('setConfiguration: ' + name + ' must be a non-negative number');
        return v;
      }
      function bool(name, v) {
        if (typeof v !== 'boolean') throw new TypeError('setConfiguration: ' + name + ' must be true or false');
        return v;
      }

      var LIVE_NUMBERS = {
        maxAllocateLifetime: 1, defaultAllocateLifetime: 1, hookTimeout: 1,
        maxConnections: 1, userQuota: 1, totalQuota: 1, maxDataSize: 1, idleTimeout: 1,
        maxPermissionsPerAllocation: 1, maxChannelsPerAllocation: 1,
        ipQuota: 1, unallocatedTimeout: 1, handshakeTimeout: 1, maxTcpConnectionsPerAllocation: 1,
      };
      var LIVE_BOOLEANS = { allowLoopback: 1, allowMulticast: 1, allowPrivatePeers: 1, allowTcpRelay: 1 };
      var FIXED = { software: 'software', secureStun: 'secureStun', checkOriginConsistency: 'checkOriginConsistency' };
      var NEVER = { listen: 1, tls: 1, dtls: 1, sniCallback: 1, SNICallback: 1, realmCallback: 1,
                    relayCallback: 1, createDTLSServer: 1, lemonTls: 1 };

      for (var key in changes) {
        if (!Object.prototype.hasOwnProperty.call(changes, key)) continue;
        var v = changes[key];

        if (key === 'relay') {
          if (!v || typeof v !== 'object') throw new TypeError('setConfiguration: relay must be an object');
          for (var rk in v) {
            if (!Object.prototype.hasOwnProperty.call(v, rk)) continue;
            var rv = v[rk];
            if (rk === 'externalIp') {
              if (rv != null && !net.isIP(rv)) throw new TypeError('setConfiguration: relay.externalIp is not an IP address: ' + rv);
              apply.push(['externalIp', rv || null]);
            } else if (rk === 'ip') {
              if (!net.isIP(rv)) throw new TypeError('setConfiguration: relay.ip is not an IP address: ' + rv);
              apply.push(['relayIp', rv]);
            } else if (rk === 'local') {
              apply.push(['relayLocal', checkRelayLocal(rv, 'setConfiguration')]);
            } else if (rk === 'portRange') {
              if (!Array.isArray(rv) || rv.length !== 2 ||
                  (rv[0] | 0) !== rv[0] || (rv[1] | 0) !== rv[1] ||
                  !(rv[0] >= 1 && rv[1] <= 65535 && rv[0] <= rv[1])) {
                throw new TypeError('setConfiguration: relay.portRange must be [low, high] within 1–65535');
              }
              apply.push(['portRange', [rv[0], rv[1]]]);
            } else {
              throw new TypeError('setConfiguration: unknown option relay.' + rk);
            }
          }
        } else if (key === 'auth') {
          if (!v || typeof v !== 'object') throw new TypeError('setConfiguration: auth must be an object');
          for (var ak in v) {
            if (!Object.prototype.hasOwnProperty.call(v, ak)) continue;
            if (ak === 'mechanism') fixed('auth.mechanism', context.authMech, v[ak]);
            else if (ak === 'realm') fixed('auth.realm', context.realm, v[ak]);
            else if (ak === 'secret' || ak === 'credentials') {
              throw new DOMException('setConfiguration: auth.' + ak + ' cannot change on a running server — use addUser / removeUser for users', 'InvalidModificationError');
            } else throw new TypeError('setConfiguration: unknown option auth.' + ak);
          }
        } else if (key === 'allowedPeers' || key === 'deniedPeers') {
          compilePeerRanges(v);   // throws TypeError on a bad range — before anything applies
          apply.push([key, v || null]);
        } else if (LIVE_NUMBERS[key]) {
          apply.push([key, num(key, v)]);
        } else if (LIVE_BOOLEANS[key]) {
          apply.push([key, bool(key, v)]);
        } else if (FIXED[key]) {
          fixed(key, context[FIXED[key]], v);
        } else if (NEVER[key]) {
          throw new DOMException('setConfiguration: ' + key + ' cannot change on a running server', 'InvalidModificationError');
        } else {
          throw new TypeError('setConfiguration: unknown option ' + key);
        }
      }

      for (var i = 0; i < apply.length; i++) context[apply[i][0]] = apply[i][1];
    },
  };

  for (var k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) this[k] = api[k];
  }

  return this;
}


// relay.local: function (ip, port) → deliver | null. See the README.
function checkRelayLocal(v, where) {
  if (v == null) return null;
  if (typeof v !== 'function') throw new TypeError(where + ': relay.local must be a function, or null');
  return v;
}


/* ====================== createServer convenience ====================== */

function createServer(options) {
  return new Server(options);
}


export { Server, createServer };
export default Server;