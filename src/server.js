
import dgram from 'node:dgram';
import net from 'node:net';
import tls from 'node:tls';
import fs from 'node:fs';
import { EventEmitter } from 'node:events';

import Socket from './socket.js';
import * as wire from './wire.js';


// Resolve lemon-tls's createDTLSServer: prefer an injected implementation,
// otherwise lazy-import 'lemon-tls'. Optional so non-DTLS users need no dep.
// cb(err, createDTLSServer).
function resolveCreateDTLSServer(config, ctx, cb) {
  var fn = config.createDTLSServer
        || (config.lemonTls && config.lemonTls.createDTLSServer)
        || ctx.createDTLSServer
        || (ctx.lemonTls && ctx.lemonTls.createDTLSServer);
  if (typeof fn === 'function') return cb(null, fn);
  import('lemon-tls').then(function(m) {
    var f = m.createDTLSServer || (m.default && m.default.createDTLSServer);
    if (typeof f !== 'function') return cb(new Error("lemon-tls has no createDTLSServer export"));
    cb(null, f);
  }).catch(function() {
    cb(new Error("dtls transport requires lemon-tls. Install it (npm i lemon-tls) " +
      "or pass createDTLSServer / lemonTls in the listen config or server options."));
  });
}

// Load a PEM cert/key that may be a path, a string, or a Buffer.
function loadPem(v) {
  if (v == null) return v;
  if (Buffer.isBuffer(v)) return v;
  if (typeof v === 'string' && v.indexOf('-----') < 0) return fs.readFileSync(v);
  return v;
}

// Resolve lemon-tls's DTLSSession constructor (for shared-socket DTLS, where
// turn-server drives the datagrams instead of letting lemon-tls own a socket).
// cb(err, DTLSSession).
function resolveDTLSSession(cfg, ctx, cb) {
  var fn = (cfg && cfg.DTLSSession)
        || (cfg && cfg.lemonTls && cfg.lemonTls.DTLSSession)
        || (ctx.lemonTls && ctx.lemonTls.DTLSSession);
  if (typeof fn === 'function') return cb(null, fn);
  import('lemon-tls').then(function(m) {
    var f = m.DTLSSession || (m.default && m.default.DTLSSession);
    if (typeof f !== 'function') return cb(new Error("lemon-tls has no DTLSSession export"));
    cb(null, f);
  }).catch(function() {
    cb(new Error("shared-socket DTLS requires lemon-tls. Install it (npm i lemon-tls) " +
      "or pass DTLSSession / lemonTls in the dtls config."));
  });
}

function Server(options) {
  if (!(this instanceof Server)) return new Server(options);
  options = options || {};

  var ev = new EventEmitter();
  var self = this;

  var listen_config = options.listen || [];
  var relay_config = options.relay || {};
  var auth_config = options.auth || {};

  var context = {
    software: options.software || null,

    // Relay config
    relayIp: relay_config.ip || '0.0.0.0',
    externalIp: relay_config.externalIp || null,
    portRange: relay_config.portRange || [49152, 65535],

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
    // need no dependency; falls back to import('lemon-tls') at listen time.
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

    // ── Built-in convenience limits (zero/null = unlimited) ──
    maxConnections: options.maxConnections || 0,
    userQuota: options.userQuota || 0,          // max allocations per username
    totalQuota: options.totalQuota || 0,         // max allocations globally
    maxDataSize: options.maxDataSize || 0,       // max DATA attribute size in bytes
    maxPermissionsPerAllocation: options.maxPermissionsPerAllocation || 0,
    maxChannelsPerAllocation: options.maxChannelsPerAllocation || 0,

    // UDP idle timeout — remove 5-tuple entry after N ms of no traffic (default 5 min)
    idleTimeout: options.idleTimeout !== undefined ? options.idleTimeout : 300000,

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
    _userAllocations: {},

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


  /* ====================== Socket factory ====================== */

  function create_client_socket(source, send_fn, localAddress) {
    // realmCallback: resolve per-client config
    // Can return string (realm only) or object { realm, mechanism, credentials, secret }
    var realm = context.realm;
    var authMech = context.authMech;
    var credentials = context.credentials;
    var secret = context.secret;

    if (context.realmCallback) {
      context.realmCallback(source, function(result) {
        if (!result) return;
        if (typeof result === 'string') {
          realm = result;
        } else {
          if (result.realm) realm = result.realm;
          if (result.mechanism) authMech = result.mechanism;
          if (result.credentials) credentials = result.credentials;
          if (result.secret) secret = result.secret;
        }
      });
    }

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
      relayCallback: context.relayCallback,
      reservations: context.relayReservations,
      maxAllocateLifetime: context.maxAllocateLifetime,
      defaultAllocateLifetime: context.defaultAllocateLifetime,
      secureStun: context.secureStun,
      checkOriginConsistency: context.checkOriginConsistency,
      allowLoopback: context.allowLoopback,
      allowMulticast: context.allowMulticast,
      localAddress: localAddress || null,
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
      ev.emit('allocate:expired', sock, alloc);
    });

    sock.on('error', function(err) {
      ev.emit('error', err);
    });

    // Stats: count real authentication failures (bad integrity, unknown user,
    // wrong credentials — NOT the initial 401 challenge of the normal flow).
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

    // userQuota: max allocations per username
    if (context.userQuota > 0) {
      sess.on('quota', function(username, cb) {
        var count = context._userAllocations[username || '_anon'] || 0;
        if (ev.listenerCount('quota') > 0) ev.emit('quota', username, cb);
        else cb(count < context.userQuota);
      });
    } else {
      sess.on('quota', function(username, cb) {
        if (ev.listenerCount('quota') > 0) ev.emit('quota', username, cb);
        else cb(true);
      });
    }

    // totalQuota: global allocation limit
    if (context.totalQuota > 0) {
      sess.on('beforeAllocate', function(info, cb) {
        if (context.stats.activeAllocations >= context.totalQuota) { cb(false); return; }
        if (ev.listenerCount('beforeAllocate') > 0) ev.emit('beforeAllocate', info, cb);
        else cb(true);
      });
    } else {
      sess.on('beforeAllocate', function(info, cb) {
        if (ev.listenerCount('beforeAllocate') > 0) ev.emit('beforeAllocate', info, cb);
        else cb(true);
      });
    }

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
    sess.on('beforePermission', function(info, cb) {
      if (context.maxPermissionsPerAllocation > 0) {
        var alloc = sess.getAllocation();
        if (alloc && Object.keys(alloc.permissions).length >= context.maxPermissionsPerAllocation) { cb(false); return; }
      }
      if (ev.listenerCount('beforePermission') > 0) ev.emit('beforePermission', info, cb);
      else cb(true);
    });

    sess.on('beforeChannelBind', function(info, cb) {
      if (context.maxChannelsPerAllocation > 0) {
        var alloc = sess.getAllocation();
        if (alloc && Object.keys(alloc.channels).length >= context.maxChannelsPerAllocation) { cb(false); return; }
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

  // UDP idle timeout: reset timer on each feed, remove client on expiry
  function setup_idle_timeout(key) {
    if (!context.idleTimeout) return null;
    return setTimeout(function() {
      var client = context.clients[key];
      if (client) {
        client.close();
        delete context.clients[key];
      }
    }, context.idleTimeout);
  }


  /* ====================== Hook helper ====================== */

  function check_hook(name, info) {
    if (ev.listenerCount(name) === 0) return true;
    var allowed = true;
    ev.emit(name, info, function(result) { allowed = !!result; });
    return allowed;
  }


  /* ====================== UDP packet processing ====================== */

  // Shared between standalone start_udp() and external handlePacket().
  // send_fn signature: send_fn(buf, dst_port, dst_ip)
  function process_udp_packet(msg, rinfo, send_fn, local_addr) {
    if (context.destroyed) return;
    if (!local_addr) return;

    var src = { ip: rinfo.address, port: rinfo.port };
    var key = make_udp_key(rinfo.address, rinfo.port, local_addr.ip, local_addr.port);

    var client = context.clients[key];
    if (!client) {
      // Reject new connections when draining
      if (context.draining) return;
      // Built-in maxConnections check
      if (context.maxConnections > 0 && context.stats.activeConnections >= context.maxConnections) return;
      // Hook: accept
      if (!check_hook('accept', { source: src, transport: 'udp' })) return;

      // Capture rinfo values in closure — locked to this 5-tuple client.
      var dst_port = rinfo.port;
      var dst_ip   = rinfo.address;

      client = create_client_socket(src, function(buf) {
        // HOT PATH: zero-copy Buffer view. buf is Uint8Array from
        // wire.encode_message — Buffer.from(u.buffer, offset, len) creates
        // a view over the same memory rather than copying ~1200 bytes.
        var out = wire.to_buffer(buf);
        send_fn(out, dst_port, dst_ip);
      }, local_addr);

      context.clients[key] = client;
      client._idleTimer = setup_idle_timeout(key);
      client._idleKey = key;

      client.on('close', function() {
        if (client._idleTimer) clearTimeout(client._idleTimer);
        delete context.clients[key];
      });
    } else if (client._idleTimer) {
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
    var send_fn = function(out, dst_port, dst_ip) {
      udp.send(out, 0, out.length, dst_port, dst_ip, function(err) {
        if (err) ev.emit('error', err);
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


  /* ====================== TCP listener ====================== */

  function start_tcp(config) {
    var port = config.port || 3478;
    var address = config.address || '0.0.0.0';

    var tcp = net.createServer(function(conn) {
      if (context.destroyed) { conn.destroy(); return; }
      // Reject new connections while draining (graceful shutdown)
      if (context.draining) { conn.destroy(); return; }
      // Built-in maxConnections check (same policy as the UDP path)
      if (context.maxConnections > 0 && context.stats.activeConnections >= context.maxConnections) {
        conn.destroy();
        return;
      }

      var src = { ip: conn.remoteAddress, port: conn.remotePort };

      // Hook: accept
      if (!check_hook('accept', { source: src, transport: 'tcp' })) {
        conn.destroy();
        return;
      }

      var tcp_buf = Buffer.alloc(0);

      var client = create_client_socket(src, function(buf) {
        // HOT PATH: zero-copy Buffer view when buf is Uint8Array.
        // TCP stream.write() accepts both Buffer and Uint8Array natively,
        // but internally optimizes for Buffer.
        if (conn.destroyed) return;
        var out = wire.to_buffer(buf);
        conn.write(out);
      }, { ip: conn.localAddress, port: conn.localPort });

      // Store by connection reference
      var key = 'tcp:' + src.ip + ':' + src.port;
      context.clients[key] = client;

      conn.on('data', function(chunk) {
        tcp_buf = Buffer.concat([tcp_buf, chunk]);

        // RFC 8489 §6.2.2: STUN over TCP is self-delimiting (no length prefix).
        while (tcp_buf.length >= 4) {
          var msg_len = wire.stun_stream_frame_length(tcp_buf, 0, tcp_buf.length);
          if (msg_len === -1) { tcp_buf = tcp_buf.slice(1); continue; }   // resync
          if (msg_len === 0 || tcp_buf.length < msg_len) break;          // wait for more data

          var frame = tcp_buf.slice(0, msg_len);
          tcp_buf = tcp_buf.slice(msg_len);
          // HOT PATH: frame is a Buffer. wire handles both Buffer and
          // Uint8Array safely (see r_bytes/validate_integrity in wire.js).
          client.feed(frame);
        }
      });

      conn.on('error', function(err) { ev.emit('error', err); });

      conn.on('close', function() {
        client.close();
        delete context.clients[key];
      });
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

    var tls_options = {
      SNICallback: sniCallback,
      // RFC 7443 — ALPN protocol identifiers for STUN/TURN
      ALPNProtocols: config.ALPNProtocols || ['stun.turn', 'stun.nat-discovery'],
    };

    // Load cert/key/ca (endpoint config, falling back to server-level tls defaults)
    var _cert = loadPem(tlsField(config, 'cert'));
    var _key  = loadPem(tlsField(config, 'key'));
    var _ca   = loadPem(tlsField(config, 'ca'));
    if (_cert && _key) { tls_options.cert = _cert; tls_options.key = _key; }
    if (_ca) tls_options.ca = _ca;

    var tls_server = tls.createServer(tls_options, function(conn) {
      if (context.destroyed) { conn.destroy(); return; }
      // Reject new connections while draining (graceful shutdown)
      if (context.draining) { conn.destroy(); return; }
      // Built-in maxConnections check (same policy as the UDP path)
      if (context.maxConnections > 0 && context.stats.activeConnections >= context.maxConnections) {
        conn.destroy();
        return;
      }

      var src = { ip: conn.remoteAddress, port: conn.remotePort };

      // Hook: accept
      if (!check_hook('accept', { source: src, transport: 'tls' })) {
        conn.destroy();
        return;
      }

      var tcp_buf = Buffer.alloc(0);

      var client = create_client_socket(src, function(buf) {
        // HOT PATH: zero-copy Buffer view over Uint8Array from wire.encode_message.
        if (conn.destroyed) return;
        var out = wire.to_buffer(buf);
        conn.write(out);
      }, { ip: conn.localAddress, port: conn.localPort });

      var key = 'tls:' + src.ip + ':' + src.port;
      context.clients[key] = client;

      conn.on('data', function(chunk) {
        tcp_buf = Buffer.concat([tcp_buf, chunk]);

        while (tcp_buf.length >= 4) {
          var msg_len = wire.stun_stream_frame_length(tcp_buf, 0, tcp_buf.length);
          if (msg_len === -1) { tcp_buf = tcp_buf.slice(1); continue; }
          if (msg_len === 0 || tcp_buf.length < msg_len) break;

          var frame = tcp_buf.slice(0, msg_len);
          tcp_buf = tcp_buf.slice(msg_len);
          // HOT PATH: Buffer → wire handles it safely.
          client.feed(frame);
        }
      });

      conn.on('error', function(err) { ev.emit('error', err); });

      conn.on('close', function() {
        client.close();
        delete context.clients[key];
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

    // Hook: accept
    if (!check_hook('accept', { source: src, transport: 'ws' })) {
      try { ws.close(); } catch(e) {}
      return;
    }

    var client = create_client_socket(src, function(buf) {
      try {
        if (ws.readyState === 1) { // OPEN
          // HOT PATH: zero-copy Buffer view. ws library accepts both
          // Buffer and Uint8Array, but Buffer is the optimized path.
          var out = wire.to_buffer(buf);
          ws.send(out);
        }
      } catch(e) {}
    });

    var key = 'ws:' + src.ip + ':' + src.port + ':' + Date.now();
    context.clients[key] = client;

    ws.on('message', function(msg) {
      if (context.destroyed) return;
      // HOT PATH: msg is usually a Buffer from ws; if it's ArrayBuffer
      // (browser-style), wrap once — no way to avoid here.
      var data = msg instanceof ArrayBuffer ? new Uint8Array(msg) : msg;
      client.feed(data);
    });

    ws.on('error', function(err) { ev.emit('error', err); });

    ws.on('close', function() {
      client.close();
      delete context.clients[key];
    });
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
        if (!check_hook('accept', { source: src, transport: 'dtls' })) {
          try { dsock.close(); } catch (e) {}
          return;
        }

        var client = create_client_socket(src, function(buf) {
          // One STUN/ChannelData message per DTLS datagram (no framing).
          try {
            var out = wire.to_buffer(buf);
            dsock.send(out);
          } catch (e) {}
        }, localAddr);

        var key2 = 'dtls:' + src.ip + ':' + src.port;
        context.clients[key2] = client;

        dsock.on('data', function(d) {
          if (context.destroyed) return;
          client.feed(d instanceof ArrayBuffer ? new Uint8Array(d) : d);
        });

        dsock.on('error', function(e) { ev.emit('error', e); });

        dsock.on('close', function() {
          client.close();
          delete context.clients[key2];
        });
      });

      dtlsServer.on('clientError', function(e) { ev.emit('error', e); });
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

    // Close any shared-socket DTLS sessions (and their idle timers).
    var dkeys = Object.keys(context.dtlsConns);
    for (var d = 0; d < dkeys.length; d++) {
      var de = context.dtlsConns[dkeys[d]];
      if (de && de.idle) { try { clearTimeout(de.idle); } catch (e) {} }
      if (de && de.session) { try { de.session.close(); } catch (e) {} }
    }
    context.dtlsConns = {};

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

    var send_fn = function(out, dst_port, dst_ip) {
      sock.send(out, 0, out.length, dst_port, dst_ip, function(err) {
        if (err) ev.emit('error', err);
      });
    };

    process_udp_packet(msg, rinfo, send_fn, localAddr);
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
      if (!check_hook('accept', { source: { ip: rinfo.address, port: rinfo.port }, transport: 'dtls' })) return;
      entry = createDtlsConn(key, rinfo, sock, localAddr);
      if (!entry) return;
    }

    if (entry.idle && typeof entry.idle.refresh === 'function') entry.idle.refresh();
    entry.session.feedDatagram(msg);
  }

  function createDtlsConn(key, rinfo, sock, localAddr) {
    var cfg = context.dtlsShared || {};
    var cert = loadPem(cfg.cert != null ? cfg.cert : (context.tlsDefaults && context.tlsDefaults.cert));
    var keyPem = loadPem(cfg.key != null ? cfg.key : (context.tlsDefaults && context.tlsDefaults.key));
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
        ca: loadPem(cfg.ca != null ? cfg.ca : (context.tlsDefaults && context.tlsDefaults.ca)),
        requestCert: cfg.requestCert,
        SNICallback: cfg.SNICallback || (context.tlsDefaults && context.tlsDefaults.SNICallback) || context.sniCallback || undefined,
        alpnProtocols: cfg.alpnProtocols || ['stun.turn', 'stun.nat-discovery'],
        minVersion: cfg.minVersion || 'DTLSv1.2',
        maxVersion: cfg.maxVersion || 'DTLSv1.3',
        mtu: cfg.mtu,
        useCookies: cfg.useCookies !== false,
      });
    } catch (e) { ev.emit('error', e); return null; }

    var entry = { session: session, client: null, idle: null };
    context.dtlsConns[key] = entry;

    var dst_ip = rinfo.address, dst_port = rinfo.port;

    function cleanup() {
      if (entry.idle) { clearTimeout(entry.idle); entry.idle = null; }
      if (entry.client) { try { entry.client.close(); } catch (e) {} }
      delete context.clients[key];
      delete context.dtlsConns[key];
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
      sock.send(out, 0, out.length, dst_port, dst_ip, function(err) { if (err) ev.emit('error', err); });
    });

    // Handshake complete → build the TURN client Socket. Outbound TURN bytes
    // are encrypted via session.send(); decrypted inbound arrives on 'data'.
    session.on('connect', function() {
      if (entry.client || context.destroyed) return;
      var client = create_client_socket({ ip: dst_ip, port: dst_port }, function(buf) {
        try { session.send(buf); } catch (e) {}
      }, localAddr);
      entry.client = client;
      context.clients[key] = client;
      client.on('close', function() { delete context.clients[key]; });
    });

    session.on('data', function(plain) {
      if (!entry.client || context.destroyed) return;
      entry.client.feed(plain instanceof ArrayBuffer ? new Uint8Array(plain) : plain);
    });

    session.on('error', function(e) { ev.emit('error', e); });
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
  };

  for (var k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) this[k] = api[k];
  }

  return this;
}


/* ====================== createServer convenience ====================== */

function createServer(options) {
  return new Server(options);
}


export { Server, createServer };
export default Server;
