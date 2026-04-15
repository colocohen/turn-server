
import dgram from 'node:dgram';
import net from 'node:net';
import tls from 'node:tls';
import fs from 'node:fs';
import { EventEmitter } from 'node:events';

import Socket from './socket.js';
import * as wire from './wire.js';


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

    listeners: [],
    clients: {},
    destroyed: false,
  };


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
      if (context._userAllocations[u]) context._userAllocations[u]--;
      ev.emit('allocate:expired', sock, alloc);
    });

    sock.on('error', function(err) {
      ev.emit('error', err);
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


  /* ====================== UDP listener ====================== */

  function start_udp(config) {
    var port = config.port || 3478;
    var address = config.address || '0.0.0.0';
    var family = address.indexOf(':') >= 0 ? 'udp6' : 'udp4';

    var udp = dgram.createSocket({ type: family, reuseAddr: true });

    udp.on('message', function(msg, rinfo) {
      if (context.destroyed) return;

      var src = { ip: rinfo.address, port: rinfo.port };
      var dst_raw = udp.address();
      var dst_addr = { ip: dst_raw.address, port: dst_raw.port };
      var key = make_udp_key(rinfo.address, rinfo.port, dst_raw.address, dst_raw.port);

      var client = context.clients[key];
      if (!client) {
        // Reject new connections when draining
        if (context.draining) return;
        // Built-in maxConnections check
        if (context.maxConnections > 0 && context.stats.activeConnections >= context.maxConnections) return;
        // Hook: accept
        if (!check_hook('accept', { source: src, transport: 'udp' })) return;

        client = create_client_socket(src, function(buf) {
          udp.send(Buffer.from(buf), 0, buf.length, rinfo.port, rinfo.address, function(err) {
            if (err) ev.emit('error', err);
          });
        }, dst_addr);

        context.clients[key] = client;
        client._idleTimer = setup_idle_timeout(key);

        client.on('close', function() {
          if (client._idleTimer) clearTimeout(client._idleTimer);
          delete context.clients[key];
        });
      }

      // Reset idle timer on each message
      if (client._idleTimer) { clearTimeout(client._idleTimer); client._idleTimer = setup_idle_timeout(key); }

      client.feed(new Uint8Array(msg));
    });

    udp.on('error', function(err) {
      ev.emit('error', err);
    });

    udp.on('listening', function() {
      var addr = udp.address();
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

      var src = { ip: conn.remoteAddress, port: conn.remotePort };

      // Hook: accept
      if (!check_hook('accept', { source: src, transport: 'tcp' })) {
        conn.destroy();
        return;
      }

      var tcp_buf = Buffer.alloc(0);

      var client = create_client_socket(src, function(buf) {
        // TCP: add 2-byte length framing
        var framed = buf;
        if (!conn.destroyed) conn.write(Buffer.from(framed));
      }, { ip: conn.localAddress, port: conn.localPort });

      // Store by connection reference
      var key = 'tcp:' + src.ip + ':' + src.port;
      context.clients[key] = client;

      conn.on('data', function(chunk) {
        tcp_buf = Buffer.concat([tcp_buf, chunk]);

        // RFC 8489 §6.2.2: STUN over TCP uses STUN's own header for framing
        // No 2-byte length prefix on dedicated TURN port
        while (tcp_buf.length >= 4) {
          var first = tcp_buf[0];
          var msg_len;

          if ((first & 0xC0) === 0x00) {
            // STUN message: 20-byte header + body length from bytes 2-3
            var body_len = (tcp_buf[2] << 8) | tcp_buf[3];
            msg_len = 20 + body_len;
          } else if (first >= 0x40 && first <= 0x4F) {
            // ChannelData: 4-byte header + data length from bytes 2-3 (padded to 4)
            var data_len = (tcp_buf[2] << 8) | tcp_buf[3];
            msg_len = 4 + data_len;
            if (msg_len % 4 !== 0) msg_len += 4 - (msg_len % 4); // pad to 4-byte boundary
          } else {
            // Unknown — skip 1 byte
            tcp_buf = tcp_buf.slice(1);
            continue;
          }

          if (tcp_buf.length < msg_len) break; // wait for more data

          var frame = tcp_buf.slice(0, msg_len);
          tcp_buf = tcp_buf.slice(msg_len);
          client.feed(new Uint8Array(frame));
        }
      });

      conn.on('error', function(err) { ev.emit('error', err); });

      conn.on('close', function() {
        client.close();
        delete context.clients[key];
      });
    });

    tcp.on('error', function(err) { ev.emit('error', err); });

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

    // SNI: per-listener callback takes priority, then server-level option
    var sniCallback = config.sniCallback || config.SNICallback || context.sniCallback || null;

    var tls_options = {
      SNICallback: sniCallback,
      // RFC 7443 — ALPN protocol identifiers for STUN/TURN
      ALPNProtocols: config.ALPNProtocols || ['stun.turn', 'stun.nat-discovery'],
    };

    // Load cert/key
    if (config.cert && config.key) {
      tls_options.cert = typeof config.cert === 'string' && config.cert.indexOf('-----') < 0
        ? fs.readFileSync(config.cert) : config.cert;
      tls_options.key = typeof config.key === 'string' && config.key.indexOf('-----') < 0
        ? fs.readFileSync(config.key) : config.key;
    }

    if (config.ca) {
      tls_options.ca = typeof config.ca === 'string' && config.ca.indexOf('-----') < 0
        ? fs.readFileSync(config.ca) : config.ca;
    }

    var tls_server = tls.createServer(tls_options, function(conn) {
      if (context.destroyed) { conn.destroy(); return; }

      var src = { ip: conn.remoteAddress, port: conn.remotePort };

      // Hook: accept
      if (!check_hook('accept', { source: src, transport: 'tls' })) {
        conn.destroy();
        return;
      }

      var tcp_buf = Buffer.alloc(0);

      var client = create_client_socket(src, function(buf) {
        var framed = buf;
        if (!conn.destroyed) conn.write(Buffer.from(framed));
      }, { ip: conn.localAddress, port: conn.localPort });

      var key = 'tls:' + src.ip + ':' + src.port;
      context.clients[key] = client;

      conn.on('data', function(chunk) {
        tcp_buf = Buffer.concat([tcp_buf, chunk]);

        while (tcp_buf.length >= 4) {
          var first = tcp_buf[0];
          var msg_len;

          if ((first & 0xC0) === 0x00) {
            var body_len = (tcp_buf[2] << 8) | tcp_buf[3];
            msg_len = 20 + body_len;
          } else if (first >= 0x40 && first <= 0x4F) {
            var data_len = (tcp_buf[2] << 8) | tcp_buf[3];
            msg_len = 4 + data_len;
            if (msg_len % 4 !== 0) msg_len += 4 - (msg_len % 4);
          } else {
            tcp_buf = tcp_buf.slice(1);
            continue;
          }

          if (tcp_buf.length < msg_len) break;

          var frame = tcp_buf.slice(0, msg_len);
          tcp_buf = tcp_buf.slice(msg_len);
          client.feed(new Uint8Array(frame));
        }
      });

      conn.on('error', function(err) { ev.emit('error', err); });

      conn.on('close', function() {
        client.close();
        delete context.clients[key];
      });
    });

    tls_server.on('error', function(err) { ev.emit('error', err); });

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
          ws.send(buf instanceof Uint8Array ? Buffer.from(buf) : buf);
        }
      } catch(e) {}
    });

    var key = 'ws:' + src.ip + ':' + src.port + ':' + Date.now();
    context.clients[key] = client;

    ws.on('message', function(msg) {
      if (context.destroyed) return;
      var data = msg instanceof ArrayBuffer ? new Uint8Array(msg) : new Uint8Array(msg);
      client.feed(data);
    });

    ws.on('error', function(err) { ev.emit('error', err); });

    ws.on('close', function() {
      client.close();
      delete context.clients[key];
    });
  }


  /* ====================== start / stop ====================== */

  function start() {
    for (var i = 0; i < listen_config.length; i++) {
      var lc = listen_config[i];
      var transport = (lc.transport || 'udp').toLowerCase();

      if (transport === 'udp') {
        start_udp(lc);
      } else if (transport === 'tcp') {
        start_tcp(lc);
      } else if (transport === 'tls') {
        start_tls(lc);
      } else if (transport === 'dtls') {
        ev.emit('error', new Error('DTLS transport not yet supported'));
      }
    }
  }

  // listen() — like Node's server.listen(). Accepts config and starts.
  // Usage:
  //   server.listen({ port: 3478 })
  //   server.listen({ port: 3478, transport: 'udp' })
  //   server.listen([{ port: 3478 }, { port: 5349, transport: 'tls', cert, key }])
  function listen(config, cb) {
    if (!config) config = [{ port: 3478, transport: 'udp' }];
    if (!Array.isArray(config)) config = [config];

    // Each item: if only port specified, start both UDP and TCP on it
    for (var i = 0; i < config.length; i++) {
      var lc = config[i];
      if (!lc.transport) {
        // Default: start UDP + TCP on same port
        listen_config.push(Object.assign({}, lc, { transport: 'udp' }));
        listen_config.push(Object.assign({}, lc, { transport: 'tcp' }));
      } else {
        listen_config.push(lc);
      }
    }

    start();
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
