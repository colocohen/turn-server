
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import net from 'node:net';
import tls from 'node:tls';
import os from 'node:os';
import { EventEmitter } from 'node:events';

import Session from './session.js';
import * as wire from './wire.js';


function Socket(options) {
  if (!(this instanceof Socket)) return new Socket(options);
  options = options || {};

  var ev = new EventEmitter();
  var self = this;

  var context = {

    options: options,
    isServer: !!options.isServer,
    destroyed: false,

    // Internal Session
    session: options.session || new Session({
      isServer: !!options.isServer,
      software: options.software || null,
      authMech: options.authMech || 'none',
      realm: options.realm || null,
      credentials: options.credentials || {},
      secret: options.secret || null,
      username: options.username || null,
      password: options.password || null,
      source: options.source || null,
      localAddress: options.localAddress || null,
      relayIp: options.relayIp || null,
      externalIp: options.externalIp || null,
      portRange: options.portRange || [49152, 65535],
      maxAllocateLifetime: options.maxAllocateLifetime || 3600,
      defaultAllocateLifetime: options.defaultAllocateLifetime || 600,
      secureStun: options.secureStun || false,
      checkOriginConsistency: options.checkOriginConsistency || false,
      allowLoopback: options.allowLoopback || false,
      allowMulticast: options.allowMulticast || false,
      // RFC 8489 §7: skip FINGERPRINT over TLS/DTLS
      useFingerprint: options.useFingerprint !== undefined ? options.useFingerprint
        : (options.transportType !== 'tls' && options.transportType !== 'dtls'),
    }),

    // Server-side: function to send data back to client (provided by Server)
    // signature: send(buf)
    sendToClient: options.send || null,

    // Client-side: transport socket to TURN server
    transport: options.transport || null, // udp socket, tcp socket, or tls socket
    transportType: options.transportType || 'udp', // 'udp' | 'tcp' | 'tls'

    // Client-side: server address
    serverHost: options.server || options.host || null,
    serverPort: options.port || 3478,

    // Server-side: relay socket (created on allocate)
    relaySocket: null,
    relayAddress: null, // { ip, port } after bind

    // Server-side: reservation tokens
    reservations: {},

    // Server-side: TCP relay connections (RFC 6062)
    tcpPeerConnections: {},  // connectionId → net.Socket

    // Server-side: secondary address for NAT detection (RFC 5780)
    secondaryAddress: options.secondaryAddress || null,
    secondarySend: options.secondarySend || null,

    // TCP framing buffer (for TCP/TLS transports)
    tcpBuffer: null,
  };

  var session = context.session;


  /* ====================== Transport → Session (incoming data) ====================== */

  // Server-side: called by Server when data arrives from the client
  function feed(data) {
    if (context.destroyed) return;
    session.message(data);
  }

  // Client-side: bind to transport and feed incoming data to session
  function bindTransport() {
    if (!context.transport) return;

    if (context.transportType === 'udp') {
      context.transport.on('message', function(msg) {
        if (context.destroyed) return;
        session.message(new Uint8Array(msg));
      });
    } else {
      // TCP / TLS — 2-byte length prefix framing
      // Use offset tracking instead of Buffer.concat to avoid copying on every chunk
      var _tcpChunks = [];
      var _tcpLen = 0;

      context.transport.on('data', function(chunk) {
        if (context.destroyed) return;
        _tcpChunks.push(chunk);
        _tcpLen += chunk.length;
        parseTcpFrames();
      });

      function compactBuffer() {
        if (_tcpChunks.length > 1) {
          _tcpChunks = [Buffer.concat(_tcpChunks)];
        }
        return _tcpChunks[0] || Buffer.alloc(0);
      }

      function consumeBytes(n) {
        _tcpLen -= n;
        var buf = compactBuffer();
        _tcpChunks = [buf.slice(n)];
        return buf.slice(0, n);
      }

      function parseTcpFrames() {
        while (_tcpLen >= 2) {
          var buf = compactBuffer();
          var frameLen = (buf[0] << 8) | buf[1];
          if (_tcpLen < 2 + frameLen) break;
          consumeBytes(2); // skip length header
          var frame = consumeBytes(frameLen);
          session.message(new Uint8Array(frame));
        }
      }
    }

    context.transport.on('error', function(err) { ev.emit('error', err); });
    context.transport.on('close', function() { ev.emit('close'); });
  }


  /* ====================== Session → Transport (outgoing data) ====================== */

  session.on('message', function(buf) {
    if (context.destroyed) return;

    if (context.sendToClient) {
      // Shared transport mode (server-side, or client-side via send function)
      context.sendToClient(buf);
    } else if (!context.isServer) {
      // Client: send to TURN server via own transport
      sendToServer(buf);
    }
  });

  function sendToServer(buf) {
    if (!context.transport || context.destroyed) return;

    if (context.transportType === 'udp') {
      var msg = Buffer.from(buf);
      context.transport.send(msg, 0, msg.length, context.serverPort, context.serverHost, function(err) {
        if (err) ev.emit('error', err);
      });
    } else {
      // TCP/TLS: add 2-byte length framing
      var framed = wire.tcp_frame(buf);
      context.transport.write(Buffer.from(framed));
    }
  }


  /* ====================== Server-side: Relay socket management ====================== */

  session.on('allocate', function(alloc) {
    if (!context.isServer) return;

    // Mark as handled — prevents session's sync fallback from firing
    alloc._confirmed = true;

    allocateRelayPort(alloc, function(err, relaySocket, address) {
      if (err) {
        if (alloc.reject) alloc.reject(err);
        else ev.emit('error', err);
        return;
      }

      context.relaySocket = relaySocket;
      context.relayAddress = address;

      // Confirm the allocation with the real relay address — this sends the response to the client
      if (alloc.confirm) {
        alloc.confirm(address);
      }

      ev.emit('allocate', alloc);
    });
  });

  session.on('allocate:expired', function(alloc) {
    if (context.relaySocket) {
      try { context.relaySocket.close(); } catch (e) {}
      context.relaySocket = null;
      context.relayAddress = null;
    }
    ev.emit('allocate:expired', alloc);
  });

  function allocateRelayPort(alloc, cb) {
    var relay_ip = context.options.relayIp || '0.0.0.0';
    var external_ip = context.options.externalIp || relay_ip;

    // Resolve 0.0.0.0 to a reachable address
    if (external_ip === '0.0.0.0' || external_ip === '::') {
      var la = session.context.localAddress;
      // Use localAddress only if it's a real routable IP (not unspecified/loopback)
      if (la && la.ip && la.ip !== '0.0.0.0' && la.ip !== '::' &&
          !la.ip.startsWith('127.') && la.ip !== '::1') {
        external_ip = la.ip;
      } else {
        // Auto-detect default non-loopback IP (consistent for all transports)
        var ifaces = os.networkInterfaces();
        var keys = Object.keys(ifaces);
        for (var ki = 0; ki < keys.length; ki++) {
          var addrs = ifaces[keys[ki]];
          for (var ai = 0; ai < addrs.length; ai++) {
            if (addrs[ai].family === 'IPv4' && !addrs[ai].internal) {
              external_ip = addrs[ai].address;
              break;
            }
          }
          if (external_ip !== '0.0.0.0') break;
        }
        // Still 0.0.0.0? Last resort: use loopback (localhost testing)
        if (external_ip === '0.0.0.0') external_ip = '127.0.0.1';
      }
    }
    var min_port = context.options.portRange ? context.options.portRange[0] : 49152;
    var max_port = context.options.portRange ? context.options.portRange[1] : 65535;

    // relayCallback: override relay config per allocation (multi-IP, geo-routing)
    if (context.options.relayCallback) {
      var relay_info = {
        username: alloc.username,
        source: session.context.source,
        requestedFamily: alloc.requestedFamily,
      };
      context.options.relayCallback(relay_info, function(config) {
        if (config) {
          if (config.ip) relay_ip = config.ip;
          if (config.externalIp) external_ip = config.externalIp;
          if (config.portRange) { min_port = config.portRange[0]; max_port = config.portRange[1]; }
        }
        doAllocate();
      });
      return;
    }

    doAllocate();

    function doAllocate() {

    var family = (alloc.requestedFamily === wire.FAMILY.IPV6) ? 'udp6' : 'udp4';

    // EVEN-PORT: find an even port (and optionally reserve next)
    var need_even = alloc.evenPort === true;
    var need_reserve = alloc.evenPort === true; // R bit

    var attempts = 0;
    var max_attempts = 100;

    function tryBind() {
      if (attempts >= max_attempts) {
        return cb(new Error('No available relay port in range'));
      }
      attempts++;

      var port;
      if (need_even) {
        // Pick a random even port
        port = min_port + Math.floor(Math.random() * ((max_port - min_port) / 2)) * 2;
        if (port % 2 !== 0) port++;
      } else {
        port = min_port + Math.floor(Math.random() * (max_port - min_port));
      }

      var sock = dgram.createSocket(family);

      sock.on('error', function() {
        try { sock.close(); } catch (e) {}
        tryBind(); // port busy, try another
      });

      sock.bind({ address: relay_ip, port: port, exclusive: true }, function() {
        var addr = sock.address();

        // DONT-FRAGMENT
        // Note: Node.js doesn't expose setsockopt(IP_DONTFRAG) natively.
        // Would require a native addon. We store the flag for future use.

        // Setup relay socket to receive data from peers
        bindRelaySocket(sock);

        // EVEN-PORT with R bit: reserve the next port (N+1)
        if (need_reserve) {
          var reserveSock = dgram.createSocket(family);
          reserveSock.on('error', function() {
            // Can't reserve N+1, try a different even port
            try { sock.close(); } catch (e) {}
            try { reserveSock.close(); } catch (e) {}
            tryBind();
          });
          reserveSock.bind({ address: relay_ip, port: port + 1, exclusive: true }, function() {
            // Store reservation token → reserved socket
            var token = new Uint8Array(crypto.randomBytes(8));
            context.reservations[Buffer.from(token).toString('hex')] = reserveSock;

            cb(null, sock, { ip: external_ip, port: addr.port });
          });
          return;
        }

        cb(null, sock, { ip: external_ip, port: addr.port });
      });
    }

    // RESERVATION-TOKEN: use previously reserved socket
    if (alloc.reservationToken) {
      var token_hex = Buffer.from(alloc.reservationToken).toString('hex');
      var reserved = context.reservations[token_hex];
      if (reserved) {
        delete context.reservations[token_hex];
        bindRelaySocket(reserved);
        var raddr = reserved.address();
        cb(null, reserved, { ip: external_ip, port: raddr.port });
        return;
      }
      return cb(new Error('Invalid reservation token'));
    }

    tryBind();
    } // end doAllocate
  }


  /* ====================== Server-side: Relay data between client and peers ====================== */

  // Synchronous hook — same pattern as Session
  function check_hook(name, info) {
    if (ev.listenerCount(name) === 0) return true;
    var allowed = true;
    ev.emit(name, info, function(result) { allowed = !!result; });
    return allowed;
  }

  function bindRelaySocket(sock) {
    sock.on('message', function(data, rinfo) {
      if (context.destroyed) return;

      var from = { ip: rinfo.address, port: rinfo.port };

      // Check permission
      if (!session.hasPermission(from.ip)) return;

      // Hook: beforeData — peer → client direction
      if (!check_hook('beforeData', {
        peer: from,
        source: session.context.source,
        username: session.getAllocation() ? session.getAllocation().username : null,
        size: data.length,
        direction: 'inbound',
      })) return; // silent drop

      // Bandwidth tracking
      session.context.bytesIn += data.length;

      // Check if there's a channel binding for this peer
      var channel = session.getChannelByPeer(from.ip, from.port);
      if (channel !== null) {
        // Send as ChannelData (more efficient)
        session.sendChannelData(channel, new Uint8Array(data));
      } else {
        // Send as Data indication
        session.sendData(from, new Uint8Array(data));
      }

      // Info event: onRelayed (peer → client, inbound)
      ev.emit('onRelayed', {
        direction: 'inbound',
        peer: from,
        source: session.context.source,
        username: session.getAllocation() ? session.getAllocation().username : null,
        size: data.length,
        channel: channel,
      });
    });

    // RFC 8656 §18.13 — report ICMP errors to client via Data indication with ICMP attribute
    sock.on('error', function(err) {
      if (context.destroyed) return;
      // Node.js UDP sockets emit errors on ICMP unreachable etc.
      // Map common errno to ICMP type/code
      var icmp_type = 3; // Destination Unreachable
      var icmp_code = 3; // Port Unreachable (default)
      if (err.code === 'ECONNREFUSED') icmp_code = 3;
      else if (err.code === 'EHOSTUNREACH') icmp_code = 1;
      else if (err.code === 'ENETUNREACH') icmp_code = 0;

      // Send notification to client via event (session can build indication)
      ev.emit('icmpError', { type: icmp_type, code: icmp_code, error: err });
    });
  }

  // Session 'relay' event: client sent a Send indication → relay to peer
  session.on('relay', function(peer, data) {
    if (!context.relaySocket || context.destroyed) return;

    context.relaySocket.send(Buffer.from(data), 0, data.length, peer.port, peer.ip, function(err) {
      if (err) ev.emit('error', err);
    });

    // Info event: onRelayed (client → peer, outbound, via Send indication)
    ev.emit('onRelayed', {
      direction: 'outbound',
      peer: peer,
      source: session.context.source,
      username: session.getAllocation() ? session.getAllocation().username : null,
      size: data.length,
      channel: null,
    });
  });

  // Session 'data' event: ChannelData from client → relay to peer
  session.on('data', function(peer, data, channel) {
    if (!context.relaySocket || context.destroyed) return;

    context.relaySocket.send(Buffer.from(data), 0, data.length, peer.port, peer.ip, function(err) {
      if (err) ev.emit('error', err);
    });

    // Info event: onRelayed (client → peer, outbound, via ChannelData)
    ev.emit('onRelayed', {
      direction: 'outbound',
      peer: peer,
      source: session.context.source,
      username: session.getAllocation() ? session.getAllocation().username : null,
      size: data.length,
      channel: channel,
    });
  });


  /* ====================== Server-side: TCP relay (RFC 6062) ====================== */

  // Session emits 'connect_peer' when client sends CONNECT request
  session.on('connect_peer', function(connectionId, peer, cb) {
    if (context.destroyed) { cb(new Error('Socket destroyed')); return; }

    var conn = net.connect({ host: peer.ip, port: peer.port }, function() {
      context.tcpPeerConnections[connectionId] = conn;
      cb(null);
    });

    conn.on('error', function(err) {
      delete context.tcpPeerConnections[connectionId];
      cb(err);
    });

    // Timeout for connection attempt
    conn.setTimeout(10000, function() {
      conn.destroy();
      delete context.tcpPeerConnections[connectionId];
      cb(new Error('Connection timeout'));
    });
  });

  // Session emits 'connection_bind' when client sends CONNECTION-BIND
  session.on('connection_bind', function(connectionId, peer, cb) {
    var conn = context.tcpPeerConnections[connectionId];
    if (!conn) { cb(new Error('No connection for ID')); return; }

    // Data from peer → send to client
    conn.on('data', function(data) {
      if (context.destroyed) return;
      session.sendData(peer, new Uint8Array(data));
    });

    conn.on('close', function() {
      delete context.tcpPeerConnections[connectionId];
    });

    cb(null);
  });


  /* ====================== Server-side: NAT detection (RFC 5780) ====================== */

  // Session emits 'change_request' when client sends BINDING with CHANGE-REQUEST
  session.on('change_request', function(msg, change, response_attrs) {
    if (!context.secondarySend) return; // no secondary address configured

    // Build the response
    var result = wire.encode_message({
      method: wire.METHOD.BINDING,
      cls: wire.CLASS.SUCCESS,
      transactionId: msg.transactionId,
      attributes: response_attrs,
    });

    // Send from secondary address (Socket layer manages this)
    context.secondarySend(result.buf, change);
  });


  /* ====================== Client-side: connect to server ====================== */

  function connect(cb) {
    if (context.isServer) return;

    if (context.transportType === 'udp') {
      var family = context.serverHost && context.serverHost.indexOf(':') >= 0 ? 'udp6' : 'udp4';
      context.transport = dgram.createSocket(family);
      context.transport.bind(0, function() {
        bindTransport();
        if (cb) cb();
        ev.emit('connect');
      });

    } else if (context.transportType === 'tcp') {
      context.transport = net.connect({
        host: context.serverHost,
        port: context.serverPort,
      }, function() {
        bindTransport();
        if (cb) cb();
        ev.emit('connect');
      });

    } else if (context.transportType === 'tls') {
      context.transport = tls.connect({
        host: context.serverHost,
        port: context.serverPort,
        servername: options.servername || context.serverHost,
        rejectUnauthorized: options.rejectUnauthorized !== false,
        ca: options.ca || undefined,
        SNICallback: options.SNICallback || undefined,
      }, function() {
        bindTransport();
        if (cb) cb();
        ev.emit('connect');
      });
    }
  }


  /* ====================== Forward session events ====================== */

  session.on('error', function(err) { ev.emit('error', err); });

  // Client-side: forward success/error events for convenience
  session.on('success', function(msg) { ev.emit('success', msg); });
  session.on('error_response', function(msg, err) { ev.emit('error_response', msg, err); });

  // Forward specific method events
  var method_names = ['binding', 'allocate', 'refresh', 'create_permission', 'channel_bind'];
  for (var mn = 0; mn < method_names.length; mn++) {
    (function(name) {
      session.on(name + ':success', function(msg) { ev.emit(name + ':success', msg); });
      session.on(name + ':error', function(msg, err) { ev.emit(name + ':error', msg, err); });
    })(method_names[mn]);
  }

  // Client-side: forward data events (from Data indication or ChannelData)
  session.on('data', function(peer, data, channel) {
    if (!context.isServer) {
      ev.emit('data', peer, data, channel);
    }
  });


  /* ====================== close / destroy ====================== */

  function close() {
    if (context.destroyed) return;
    context.destroyed = true;

    session.close();

    if (context.relaySocket) {
      try { context.relaySocket.close(); } catch (e) {}
      context.relaySocket = null;
    }

    // Close reservation sockets
    var rkeys = Object.keys(context.reservations);
    for (var i = 0; i < rkeys.length; i++) {
      try { context.reservations[rkeys[i]].close(); } catch (e) {}
    }
    context.reservations = {};

    // Close TCP relay peer connections
    var ckeys = Object.keys(context.tcpPeerConnections);
    for (var j = 0; j < ckeys.length; j++) {
      try { context.tcpPeerConnections[ckeys[j]].destroy(); } catch (e) {}
    }
    context.tcpPeerConnections = {};

    if (!context.isServer && context.transport) {
      if (context.transportType === 'udp') {
        try { context.transport.close(); } catch (e) {}
      } else {
        try { context.transport.end(); } catch (e) {}
      }
    }

    ev.emit('close');
  }


  /* ====================== API ====================== */

  var api = {
    context: context,
    isServer: context.isServer,

    on:  function(name, fn) { ev.on(name, fn); },
    off: function(name, fn) { ev.off(name, fn); },

    /** Feed incoming data (server-side, called by Server) */
    feed: feed,

    /** Connect to TURN server (client-side) */
    connect: connect,

    /** Get the internal Session */
    getSession: function() { return session; },

    /** Close socket and release resources */
    close: close,

    // ---- Session passthrough (server-side) ----

    addUser: function(u, p) { session.addUser(u, p); },
    removeUser: function(u) { session.removeUser(u); },
    set_context: function(opts) { session.set_context(opts); },

    hasPermission: function(ip) { return session.hasPermission(ip); },
    getPeerByChannel: function(n) { return session.getPeerByChannel(n); },
    getChannelByPeer: function(ip, port) { return session.getChannelByPeer(ip, port); },
    getAllocation: function() { return session.getAllocation(); },
    getRelayAddress: function() { return context.relayAddress; },

    // ---- Client-side convenience ----

    binding: function(attrs, cb) { session.binding(attrs, cb); },
    allocate: function(opts, cb) { session.allocate(opts, cb); },
    refresh: function(lifetime, cb) { session.refresh(lifetime, cb); },
    createPermission: function(peers, cb) { session.createPermission(peers, cb); },
    channelBind: function(channel, peer, cb) { session.channelBind(channel, peer, cb); },

    /** Send data to a peer via Send indication */
    send: function(peer, data) { session.send(peer, data); },

    /** Send data to a peer via ChannelData (must have channel binding) */
    sendChannel: function(channel, data) { session.sendChannelData(channel, data); },

    // RFC 6062 — TCP relay (client-side)
    connectPeer: function(peer, cb) { session.connect(peer, cb); },
    connectionBind: function(connectionId, cb) { session.connectionBind(connectionId, cb); },
  };

  for (var k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) this[k] = api[k];
  }

  // If client-side transport was passed directly, bind it
  if (!context.isServer && context.transport) {
    bindTransport();
  }

  return this;
}


export default Socket;
