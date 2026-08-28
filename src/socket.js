
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import net from 'node:net';
import tls from 'node:tls';
import os from 'node:os';
import { EventEmitter } from 'node:events';

import Session from './session.js';
import * as wire from './wire.js';


// Zero-copy Uint8Array → Buffer conversion. Node's dgram.send() and
// stream.write() accept Uint8Array since Node 18, but internally some
// paths are optimized for Buffer. Buffer.from(u.buffer, ...) creates a
// Buffer *view* over the same memory — no copy.
function toBuffer(u) {
  if (Buffer.isBuffer(u)) return u;
  return Buffer.from(u.buffer, u.byteOffset, u.byteLength);
}

// Normalize an inbound datagram payload to something session.message accepts
// (Buffer or Uint8Array). lemon-tls emits Uint8Array on 'data'.
function toMsg(d) {
  if (Buffer.isBuffer(d) || d instanceof Uint8Array) return d;
  if (d instanceof ArrayBuffer) return new Uint8Array(d);
  if (d && d.buffer) return new Uint8Array(d.buffer, d.byteOffset, d.byteLength);
  return d;
}

// Resolve lemon-tls's connectDTLS: prefer an injected implementation
// (options.connectDTLS), otherwise lazy-import 'lemon-tls'. Kept optional so
// turn-server has no hard dependency for non-DTLS users. cb(err, connectDTLS).
function resolveConnectDTLS(options, cb) {
  if (typeof options.connectDTLS === 'function') return cb(null, options.connectDTLS);
  if (options.lemonTls && typeof options.lemonTls.connectDTLS === 'function') {
    return cb(null, options.lemonTls.connectDTLS);
  }
  import('lemon-tls').then(function(m) {
    var fn = m.connectDTLS || (m.default && m.default.connectDTLS);
    if (typeof fn !== 'function') return cb(new Error("lemon-tls has no connectDTLS export"));
    cb(null, fn);
  }).catch(function() {
    cb(new Error("DTLS transport requires lemon-tls. Install it (npm i lemon-tls) " +
      "or pass options.connectDTLS / options.lemonTls."));
  });
}



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
      // Carried into hook payloads (beforeBindingResponse) so they can report
      // the same transport label the accept hook sees.
      transportType: options.transportType || null,
      hookTimeout: options.hookTimeout,
      relayIp: options.relayIp || null,
      externalIp: options.externalIp || null,
      portRange: options.portRange || [49152, 65535],
      maxAllocateLifetime: options.maxAllocateLifetime || 3600,
      defaultAllocateLifetime: options.defaultAllocateLifetime || 600,
      secureStun: options.secureStun || false,
      checkOriginConsistency: options.checkOriginConsistency || false,
      allowLoopback: options.allowLoopback || false,
      allowMulticast: options.allowMulticast || false,
      // RFC 8489 §7: skip FINGERPRINT over TLS/DTLS (wss = WebSocket over TLS)
      useFingerprint: options.useFingerprint !== undefined ? options.useFingerprint
        : (options.transportType !== 'tls' && options.transportType !== 'dtls'
           && options.transportType !== 'wss'),
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

    // Server-side: reservation tokens (RFC 5766 §14.9).
    // A reserved port must be claimable from a NEW allocation — i.e. from a
    // DIFFERENT 5-tuple — so the map is shared across all client Sockets:
    // Server passes one shared object via options.reservations. A standalone
    // Socket (no Server) falls back to a private map and owns its cleanup.
    // Entry shape: tokenHex → { socket, timer } (timer = 30s expiry, §14.9).
    reservations: options.reservations || {},
    ownsReservations: !options.reservations,

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
        // HOT PATH: msg is a Buffer. With r_bytes/validate_integrity fixed
        // to detach when needed, passing Buffer directly is safe and saves
        // a ~1200-byte copy per incoming packet.
        session.message(msg);
      });
      context.transport.on('error', function(err) { ev.emit('error', err); });
      context.transport.on('close', function() { ev.emit('close'); });

    } else if (context.transportType === 'dtls') {
      // DTLS preserves datagram boundaries — each 'data' event is exactly one
      // decrypted STUN/ChannelData message. No framing of our own (like UDP).
      // context.transport is a lemon-tls DTLSSocket.
      context.transport.on('data', function(d) {
        if (context.destroyed) return;
        session.message(toMsg(d));
      });
      context.transport.on('error', function(err) { ev.emit('error', err); });
      context.transport.on('close', function() { ev.emit('close'); });

    } else if (context.transportType === 'ws' || context.transportType === 'wss') {
      // WebSocket — the WS protocol already delimits messages, so each
      // incoming message is exactly one STUN/ChannelData frame. No stream
      // framing of our own. Works with the global WebSocket (Node >= 22),
      // the browser WebSocket, or any injected `options.WebSocket`.
      context.transport.binaryType = 'arraybuffer';
      context.transport.onmessage = function(event) {
        if (context.destroyed) return;
        var d = event.data;
        var frame = (d instanceof ArrayBuffer) ? new Uint8Array(d)
                  : Buffer.isBuffer(d) ? d
                  : (d && d.buffer) ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength)
                  : d;
        session.message(frame);
      };
      context.transport.onerror = function(e) { ev.emit('error', e && e.error ? e.error : new Error('WebSocket error')); };
      context.transport.onclose = function() { ev.emit('close'); };

    } else {
      // TCP / TLS — RFC 8489 §7.2: STUN over TCP is NOT length-prefixed.
      // Messages are self-delimiting: STUN by its 20-byte header + length
      // field, ChannelData by its 4-byte header + length (padded to 4).
      // This matches what the server emits (server.js start_tcp/start_tls)
      // and what coturn / browsers send. (The previous 2-byte tcp_frame()
      // prefix was a mismatch that broke client<->server TCP entirely.)
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

      function parseTcpFrames() {
        while (_tcpLen >= 4) {
          var buf = compactBuffer();
          var msgLen = wire.stun_stream_frame_length(buf, 0, _tcpLen);
          if (msgLen === -1) { _tcpChunks = [buf.slice(1)]; _tcpLen -= 1; continue; } // resync
          if (msgLen === 0 || _tcpLen < msgLen) break;                                 // wait for more
          var frame = buf.slice(0, msgLen);
          _tcpChunks = [buf.slice(msgLen)];
          _tcpLen -= msgLen;
          // HOT PATH: frame is a Buffer — pass directly, no wrapping.
          session.message(frame);
        }
      }

      context.transport.on('error', function(err) { ev.emit('error', err); });
      context.transport.on('close', function() { ev.emit('close'); });
    }
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
      // HOT PATH: buf is Uint8Array from wire.encode_message. toBuffer() gives
      // a zero-copy Buffer view over the same memory.
      var msg = toBuffer(buf);
      context.transport.send(msg, 0, msg.length, context.serverPort, context.serverHost, function(err) {
        if (err) ev.emit('error', err);
      });
    } else if (context.transportType === 'ws' || context.transportType === 'wss') {
      // WebSocket frames the message for us — send one STUN/ChannelData frame
      // as one binary WS message. No 2-byte prefix.
      if (context.transport.readyState === 1 /* OPEN */) {
        context.transport.send(toBuffer(buf));
      }
    } else if (context.transportType === 'dtls') {
      // One DTLS datagram per STUN/ChannelData message (no framing, like UDP).
      context.transport.send(toBuffer(buf));
    } else {
      // TCP/TLS — RFC 8489 §7.2: send raw STUN, self-delimited by its own
      // header length. NO 2-byte tcp_frame() prefix (that was the bug).
      context.transport.write(toBuffer(buf));
    }
  }


  /* ====================== Server-side: Relay socket management ====================== */

  session.on('allocate', function(alloc) {
    if (!context.isServer) return;

    // Mark as handled — prevents session's sync fallback from firing
    alloc._confirmed = true;

    allocateRelayPort(alloc, function(err, relaySocket, address, reservationToken) {
      if (err) {
        if (alloc.reject) alloc.reject(err);
        else ev.emit('error', err);
        return;
      }

      context.relaySocket = relaySocket;
      context.relayAddress = address;

      // Confirm the allocation with the real relay address — this sends the
      // response to the client (including RESERVATION-TOKEN when port+1 was
      // reserved via EVEN-PORT's R bit).
      if (alloc.confirm) {
        alloc.confirm(address, reservationToken ? { reservationToken: reservationToken } : null);
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

    // EVEN-PORT (RFC 5766 §14.6): presence requests an even port; the R bit
    // additionally reserves port+1 (claimed later via RESERVATION-TOKEN).
    var need_even = alloc.evenPort != null;
    var need_reserve = !!(alloc.evenPort && (alloc.evenPort === true || alloc.evenPort.reserve));

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

      // Bind-retry handler: fires when the port is busy. It MUST be detached
      // once the bind succeeds — otherwise a later runtime error on the relay
      // socket (e.g. ICMP-driven errors on some platforms) would re-enter
      // tryBind() and silently swap the relay socket to a NEW port, while the
      // client was already told the OLD relay address in the Allocate response.
      function onBindError() {
        try { sock.close(); } catch (e) {}
        tryBind(); // port busy, try another
      }
      sock.once('error', onBindError);

      sock.bind({ address: relay_ip, port: port, exclusive: true }, function() {
        sock.removeListener('error', onBindError);
        var addr = sock.address();

        // DONT-FRAGMENT
        // Note: Node.js doesn't expose setsockopt(IP_DONTFRAG) natively.
        // Would require a native addon. We store the flag for future use.

        // Setup relay socket to receive data from peers
        bindRelaySocket(sock);

        // EVEN-PORT with R bit: reserve the next port (N+1)
        if (need_reserve) {
          var reserveSock = dgram.createSocket(family);
          function onReserveBindError() {
            // Can't reserve N+1, try a different even port
            try { sock.close(); } catch (e) {}
            try { reserveSock.close(); } catch (e) {}
            tryBind();
          }
          reserveSock.once('error', onReserveBindError);
          reserveSock.bind({ address: relay_ip, port: port + 1, exclusive: true }, function() {
            reserveSock.removeListener('error', onReserveBindError);
            // The reserved socket sits idle until claimed via RESERVATION-TOKEN;
            // keep a handler attached so a stray error can't crash the process.
            reserveSock.on('error', function(err) { ev.emit('error', err); });

            // Store reservation token → reserved socket. RFC 5766 §14.9:
            // the server MUST hold the reservation for at least 30 seconds;
            // after that, release the port.
            var token = new Uint8Array(crypto.randomBytes(8));
            var tokenHex = Buffer.from(token).toString('hex');
            var ttl = setTimeout(function() {
              var entry = context.reservations[tokenHex];
              if (!entry) return;
              delete context.reservations[tokenHex];
              try { entry.socket.close(); } catch (e) {}
            }, 30000);
            if (ttl.unref) ttl.unref();
            context.reservations[tokenHex] = { socket: reserveSock, timer: ttl };

            // Hand the token up so the Allocate success can carry
            // RESERVATION-TOKEN (see session alloc.confirm).
            cb(null, sock, { ip: external_ip, port: addr.port }, token);
          });
          return;
        }

        cb(null, sock, { ip: external_ip, port: addr.port });
      });
    }

    // RESERVATION-TOKEN: use previously reserved socket
    if (alloc.reservationToken) {
      var token_hex = Buffer.from(alloc.reservationToken).toString('hex');
      var entry = context.reservations[token_hex];
      if (entry) {
        delete context.reservations[token_hex];
        if (entry.timer) clearTimeout(entry.timer);
        var reserved = entry.socket;
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
  // Relay hot path only (beforeData). Called once per inbound packet, so it
  // stays synchronous — a deferred decision here would reorder media and
  // allocate per datagram. Listeners must answer in the same tick. Every other
  // hook goes through Session's async check_hook.
  function check_hook_sync(name, info) {
    if (ev.listenerCount(name) === 0) return true;
    var allowed = true;
    ev.emit(name, info, function(result) { allowed = !!result; });
    return allowed;
  }

  // Map a Node.js UDP send errno to an ICMP { type, code } (RFC 8656 §11.5).
  // Family-aware: ICMPv4 Destination Unreachable is type 3; ICMPv6 (RFC 4443)
  // is type 1 with different codes, Packet Too Big is type 2.
  // Returns null for errors that don't correspond to an ICMP condition.
  function errnoToIcmp(err, peerIp) {
    if (!err || !err.code) return null;
    var v6 = peerIp && peerIp.indexOf(':') >= 0;
    switch (err.code) {
      case 'ECONNREFUSED': return v6 ? { type: 1, code: 4, data: 0 } : { type: 3, code: 3, data: 0 }; // port unreachable
      case 'EHOSTUNREACH': return v6 ? { type: 1, code: 3, data: 0 } : { type: 3, code: 1, data: 0 }; // host unreachable
      case 'ENETUNREACH':  return v6 ? { type: 1, code: 0, data: 0 } : { type: 3, code: 0, data: 0 }; // net unreachable
      case 'EMSGSIZE':     return v6 ? { type: 2, code: 0, data: 0 } : { type: 3, code: 4, data: 0 }; // frag needed / too big
      default: return null;
    }
  }

  // Relay send failed for a known peer → RFC 8656 §11.5: tell the client via
  // a Data indication carrying XOR-PEER-ADDRESS + ICMP (no DATA attribute).
  // Non-ICMP-like errors still surface on the 'error' event as before.
  function reportRelaySendError(peer, err) {
    var icmp = errnoToIcmp(err, peer && peer.ip);
    if (icmp) {
      try { session.sendIcmpError(peer, icmp); } catch (e) {}
      ev.emit('icmpError', { type: icmp.type, code: icmp.code, peer: peer, error: err });
    } else {
      ev.emit('error', err);
    }
  }

  function bindRelaySocket(sock) {
    sock.on('message', function(data, rinfo) {
      if (context.destroyed) return;

      var from = { ip: rinfo.address, port: rinfo.port };

      // Check permission
      if (!session.hasPermission(from.ip)) return;

      // Hook: beforeData — peer → client direction. Short-circuit on
      // listenerCount FIRST so the info object isn't allocated per packet when
      // no hook is registered (this is the relay hot path).
      if (ev.listenerCount('beforeData') > 0 && !check_hook_sync('beforeData', {
        peer: from,
        source: session.context.source,
        username: session.getAllocation() ? session.getAllocation().username : null,
        size: data.length,
        direction: 'inbound',
      })) return; // silent drop

      // Bandwidth tracking
      session.context.bytesIn += data.length;
      session.context.packetsIn++;

      // Check if there's a channel binding for this peer
      var channel = session.getChannelByPeer(from.ip, from.port);
      if (channel !== null) {
        // Send as ChannelData (more efficient). `data` is Buffer from dgram —
        // pass directly, wire.encode_channel_data works on both Buffer and Uint8Array.
        session.sendChannelData(channel, data);
      } else {
        // Send as Data indication
        session.sendData(from, data);
      }

      // Info event: onRelayed (peer → client, inbound). Guard allocation.
      if (ev.listenerCount('onRelayed') > 0) ev.emit('onRelayed', {
        direction: 'inbound',
        peer: from,
        source: session.context.source,
        username: session.getAllocation() ? session.getAllocation().username : null,
        size: data.length,
        channel: channel,
      });
    });

    // Socket-level errors have no peer attached (Node doesn't tell us which
    // datagram triggered them), so we can't build an RFC 8656 §11.5 indication
    // here — the per-send callbacks above handle that. Surface for observability.
    sock.on('error', function(err) {
      if (context.destroyed) return;
      var icmp = errnoToIcmp(err) || { type: 3, code: 3 };
      ev.emit('icmpError', { type: icmp.type, code: icmp.code, peer: null, error: err });
    });
  }

  // Session 'relay' event: client sent a Send indication → relay to peer
  session.on('relay', function(peer, data) {
    if (!context.relaySocket || context.destroyed) return;

    // HOT PATH: zero-copy Buffer view (was Buffer.from(data) which copied).
    var out = toBuffer(data);
    context.relaySocket.send(out, 0, out.length, peer.port, peer.ip, function(err) {
      if (err) reportRelaySendError(peer, err);
    });

    // Info event: onRelayed (client → peer, outbound, via Send indication)
    if (ev.listenerCount('onRelayed') > 0) ev.emit('onRelayed', {
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

    // HOT PATH: zero-copy Buffer view. ChannelData is typically 30-50 pkt/sec
    // per active channel in media calls — saves a 1200-byte copy per RTP.
    var out = toBuffer(data);
    context.relaySocket.send(out, 0, out.length, peer.port, peer.ip, function(err) {
      if (err) reportRelaySendError(peer, err);
    });

    // Info event: onRelayed (client → peer, outbound, via ChannelData)
    if (ev.listenerCount('onRelayed') > 0) ev.emit('onRelayed', {
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

    // Data from peer → send to client. `data` is already a Buffer.
    conn.on('data', function(data) {
      if (context.destroyed) return;
      session.sendData(peer, data);
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

    // Forwards transport errors that occur before bindTransport() runs (i.e.
    // during TCP connect / TLS handshake). Detached on successful connect so
    // the persistent handler in bindTransport() is the only one afterward.
    function _preErr(err) { ev.emit('error', err); }

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
        if (typeof context.transport.off === 'function') context.transport.off('error', _preErr);
        bindTransport();
        if (cb) cb();
        ev.emit('connect');
      });
      // Capture connect-phase errors (ECONNREFUSED, etc.) before bindTransport
      // attaches the persistent handler. Detached above on successful connect.
      context.transport.on('error', _preErr);

    } else if (context.transportType === 'tls') {
      context.transport = tls.connect({
        host: context.serverHost,
        port: context.serverPort,
        servername: options.servername || context.serverHost,
        rejectUnauthorized: options.rejectUnauthorized !== false,
        ca: options.ca || undefined,
        SNICallback: options.SNICallback || undefined,
      }, function() {
        if (typeof context.transport.off === 'function') context.transport.off('error', _preErr);
        bindTransport();
        if (cb) cb();
        ev.emit('connect');
      });
      // Capture handshake-phase errors (cert rejection, ECONNREFUSED) before
      // bindTransport attaches the persistent handler. Detached on 'secureConnect'.
      context.transport.on('error', _preErr);

    } else if (context.transportType === 'ws' || context.transportType === 'wss') {
      // WebSocket client. Zero-dep by default via the global WebSocket
      // (Node >= 22 / browsers). For older Node or custom transports, inject
      // an implementation through options.WebSocket.
      var WS = options.WebSocket
        || (typeof WebSocket !== 'undefined' ? WebSocket : null)
        || (typeof globalThis !== 'undefined' ? globalThis.WebSocket : null);
      if (!WS) {
        ev.emit('error', new Error(
          'WebSocket transport requires a global WebSocket (Node >= 22) ' +
          'or options.WebSocket (e.g. the "ws" package).'));
        return;
      }

      var scheme = (context.transportType === 'wss') ? 'wss' : 'ws';
      var path = options.wsPath || '/';
      var hostPart = (context.serverHost && context.serverHost.indexOf(':') >= 0)
        ? '[' + context.serverHost + ']' : context.serverHost;
      var url = options.wsUrl || (scheme + '://' + hostPart + ':' + context.serverPort + path);

      var wsOpts;
      if (context.transportType === 'wss') {
        // 'ws' package honours these; the global/browser WebSocket ignores extra args.
        wsOpts = {
          rejectUnauthorized: options.rejectUnauthorized !== false,
          ca: options.ca || undefined,
          servername: options.servername || context.serverHost,
        };
      }

      try {
        context.transport = wsOpts ? new WS(url, wsOpts) : new WS(url);
      } catch (e) {
        ev.emit('error', e);
        return;
      }
      context.transport.binaryType = 'arraybuffer';

      var _opened = false;
      context.transport.onopen = function() {
        if (_opened) return; _opened = true;
        bindTransport();
        if (cb) cb();
        ev.emit('connect');
      };
      // bindTransport sets onmessage/onerror/onclose; onopen above is enough here.

    } else if (context.transportType === 'dtls') {
      // DTLS client via lemon-tls connectDTLS (datagram transport over UDP).
      // RFC 7350: STUN/TURN over DTLS. RFC 7350 also defines ALPN ids.
      resolveConnectDTLS(options, function(err, connectDTLS) {
        if (err) { ev.emit('error', err); return; }
        var dsock;
        try {
          dsock = connectDTLS({
            host: context.serverHost,
            port: context.serverPort,
            servername: options.servername || context.serverHost,
            rejectUnauthorized: options.rejectUnauthorized !== false,
            ca: options.ca || undefined,
            alpnProtocols: options.alpnProtocols || ['stun.turn', 'stun.nat-discovery'],
            minVersion: options.minVersion || 'DTLSv1.2',
            maxVersion: options.maxVersion || 'DTLSv1.3',
            mtu: options.mtu,
          });
        } catch (e) { ev.emit('error', e); return; }

        context.transport = dsock;

        function preErr(e) { ev.emit('error', e); }

        var _connected = false;
        function onConn() {
          if (_connected) return; _connected = true;
          if (typeof dsock.off === 'function') {
            dsock.off('connect', onConn);
            dsock.off('error', preErr);
          }
          bindTransport();          // wires 'data' / 'error' / 'close'
          if (cb) cb();
          ev.emit('connect');
        }
        dsock.on('connect', onConn);
        // Surface pre-handshake errors (handshake timeout, cert rejection, …)
        dsock.on('error', preErr);
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

  // Client-side: forward ICMP error notifications from the server
  // (RFC 8656 §11.5 — Data indication with XOR-PEER-ADDRESS + ICMP).
  session.on('icmp', function(peer, icmp) {
    if (!context.isServer) {
      ev.emit('icmp', peer, icmp);
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

    // Close reservation sockets — but ONLY when this Socket owns the map.
    // Under a Server the map is shared across all clients (a token issued
    // here must be claimable from a different 5-tuple); the Server sweeps
    // it in stop(), and each entry has its own 30s TTL anyway.
    if (context.ownsReservations) {
      var rkeys = Object.keys(context.reservations);
      for (var i = 0; i < rkeys.length; i++) {
        var rentry = context.reservations[rkeys[i]];
        if (rentry && rentry.timer) clearTimeout(rentry.timer);
        try { (rentry && rentry.socket ? rentry.socket : rentry).close(); } catch (e) {}
        delete context.reservations[rkeys[i]];
      }
    }

    // Close TCP relay peer connections
    var ckeys = Object.keys(context.tcpPeerConnections);
    for (var j = 0; j < ckeys.length; j++) {
      try { context.tcpPeerConnections[ckeys[j]].destroy(); } catch (e) {}
    }
    context.tcpPeerConnections = {};

    if (!context.isServer && context.transport) {
      if (context.transportType === 'udp') {
        try { context.transport.close(); } catch (e) {}
      } else if (context.transportType === 'ws' || context.transportType === 'wss') {
        try { context.transport.close(); } catch (e) {}
      } else if (context.transportType === 'dtls') {
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
