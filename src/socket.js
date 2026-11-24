import { random_bytes_sync } from 'cryptographic-primitives/random.js';
import dgram from 'node:dgram';
import net from 'node:net';
import lemonTls from 'lemon-tls';
import os from 'node:os';
import util from 'node:util';
import { EventEmitter } from 'node:events';

import Session from './session.js';
import * as wire from './wire.js';
import { checkedSocketBufferSize, udpSocketOptions } from './udp_buffers.js';


// ─── Relays this process owns, by the address the world sees them at ────
//
// Two clients relaying through the same server — the usual case when both
// are behind NATs that need TURN, and the case every self-test has — means
// relay A sending to relay B's address: this server's own external IP. Put on
// the network, that datagram leaves for the router and must be turned around
// there (NAT hairpinning). Behind a home router it mostly is not, for UDP: the
// allocations succeed, the permissions are in place, and nothing arrives. A
// WebRTC call between two such users simply never connects, with no error.
//
// So a datagram addressed to one of our own relays is handed to it directly —
// through the same 'message' handler a network datagram takes, with the
// sender's external relay address as its source. Permissions, hooks and
// accounting apply exactly as they would.
var localRelays = new Map();   // "ip:port" -> Socket context
function relayKey(addr) { return addr ? addr.ip + ':' + addr.port : null; }

// The addresses our relays are announced on (ip -> number of live relays). A
// peer address that is one of them is this server itself — see the peer
// policy exemption in Session (isOwnRelayIp).
var localRelayIps = new Map();
function addRelayIp(ip) { if (ip) localRelayIps.set(ip, (localRelayIps.get(ip) || 0) + 1); }
function removeRelayIp(ip) {
  var n = localRelayIps.get(ip);
  if (!n) return;
  if (n <= 1) localRelayIps.delete(ip); else localRelayIps.set(ip, n - 1);
}
function isOwnRelayIp(ip) { return localRelayIps.size > 0 && localRelayIps.has(ip); }


// ─── RFC 6062 TCP relay ─────────────────────────────────────────────────
//
// Peer data connections by CONNECTION-ID, process-wide. The ConnectionBind
// that claims one arrives on a NEW connection from the client — another
// Socket, another Session — so the id must be found from there.
// id -> { id, peer, sock, state: 'connecting' | 'pending' | 'bound',
//         owner (the allocation's Socket context), username, realm, timer }
var tcpRelayConns = new Map();
function newConnectionId() {
  var id;
  do { id = Buffer.from(random_bytes_sync(4)).readUInt32BE(0); } while (id === 0 || tcpRelayConns.has(id));
  return id;
}

// TCP relay ports this process listens on. The listeners are opened with
// SO_REUSEPORT (see connectFromRelay), which would also let a second
// listener of ours join the same port; they are kept apart by this set.
var tcpRelayPorts = new Set();

// The relayed address is the local end of the connections the server opens
// to peers (RFC 6062 §5.2), while it also listens there (§5.3). Linux binds
// a second socket to a listening port only when both have SO_REUSEPORT, and
// Node sets it on a listener (reusePort) but not on a connecting socket. So
// the connecting socket is made from Node's own TCP handle, bound with the
// reuse-port flag, then connected and wrapped in a net.Socket.
// null when this runtime has no such handle (not Node, or a Node that
// removed it): connections then leave from the relay IP and a port of the
// system's choosing — a warning says so, once.
var UV_TCP_REUSEPORT = 2;
var _tcpWrap;
function tcpWrapBinding() {
  if (_tcpWrap !== undefined) return _tcpWrap;
  _tcpWrap = null;
  try {
    var b = process.binding('tcp_wrap');
    if (b && typeof b.TCP === 'function' && typeof b.TCPConnectWrap === 'function' && b.constants) _tcpWrap = b;
  } catch (e) {}
  return _tcpWrap;
}
var _warnedEphemeral = false;
function warnEphemeral(why) {
  if (_warnedEphemeral) return;
  _warnedEphemeral = true;
  try {
    process.emitWarning('TURN TCP relay: connections to peers leave from an ephemeral port, not the relayed ' +
      'address (RFC 6062 §5.2): ' + why, 'TurnTcpRelayWarning');
  } catch (e) {}
}

function sysError(status, syscall) {
  var name = 'UNKNOWN';
  try { name = util.getSystemErrorName(status); } catch (e) {}
  var err = new Error(syscall + ' ' + name);
  err.code = name; err.errno = status; err.syscall = syscall;
  return err;
}

// Open a TCP connection to `peer` from `local` ({ ip, port, reusePort }).
// cb(err) or cb(null, socket) — the socket handed over paused: what the peer
// sends waits in the kernel, its receive window shrinking, until somebody
// reads (RFC 6062 §5.2: buffer, and let the window show it).
function connectFromRelay(local, peer, timeoutMs, cb) {
  var done = false;
  var timer = null;
  function finish(err, sock) {
    if (done) return;
    done = true;
    if (timer) { clearTimeout(timer); timer = null; }
    cb(err, sock);
  }

  var tw = local.reusePort ? tcpWrapBinding() : null;
  if (!tw) {
    warnEphemeral(local.reusePort ? 'no TCP handle in this runtime' : 'the relay listener has no SO_REUSEPORT');
    var opts = { host: peer.ip, port: peer.port, noDelay: true };
    if (local.ip && local.ip !== '0.0.0.0' && local.ip !== '::') opts.localAddress = local.ip;
    var c = net.connect(opts);
    c.pause();
    c.on('connect', function() { c.removeListener('error', onErr); finish(null, c); });
    function onErr(err) { c.destroy(); finish(err); }
    c.on('error', onErr);
    timer = setTimeout(function() { c.destroy(); finish(Object.assign(new Error('connect timeout'), { code: 'ETIMEDOUT' })); }, timeoutMs);
    if (timer.unref) timer.unref();
    return;
  }

  var v6 = net.isIPv6(peer.ip);
  var h = new tw.TCP(tw.constants.SOCKET);
  var rc = v6 ? h.bind6(local.ip, local.port, UV_TCP_REUSEPORT) : h.bind(local.ip, local.port, UV_TCP_REUSEPORT);
  if (rc) { try { h.close(); } catch (e) {} return finish(sysError(rc, 'bind')); }

  var req = new tw.TCPConnectWrap();
  req.oncomplete = function(status) {
    if (done) return;                      // timed out; the handle is closed
    if (status < 0) { try { h.close(); } catch (e) {} return finish(sysError(status, 'connect')); }
    var sock;
    try {
      sock = new net.Socket({ handle: h, readable: true, writable: true, pauseOnCreate: true });
    } catch (e) { try { h.close(); } catch (e2) {} return finish(e); }
    sock.setNoDelay(true);
    finish(null, sock);
  };
  req.address = peer.ip;
  req.port = peer.port;
  req.localAddress = local.ip;
  req.localPort = local.port;
  var crc = v6 ? h.connect6(req, peer.ip, peer.port) : h.connect(req, peer.ip, peer.port);
  if (crc) { try { h.close(); } catch (e) {} return finish(sysError(crc, 'connect')); }
  timer = setTimeout(function() {
    try { h.close(); } catch (e) {}
    finish(Object.assign(new Error('connect timeout'), { code: 'ETIMEDOUT' }));
  }, timeoutMs);
  if (timer.unref) timer.unref();
}

// An IPv4 peer on a dual-stack listener shows up as ::ffff:a.b.c.d.
function unmapIp(ip) {
  return typeof ip === 'string' && ip.indexOf('::ffff:') === 0 && net.isIPv4(ip.slice(7)) ? ip.slice(7) : ip;
}

function stunError(code, message) {
  var e = new Error(message || ('STUN ' + code));
  e.stunCode = code;
  return e;
}

// RFC 6062 timers: the time a peer data connection waits for its
// ConnectionBind (§5.2, §5.3), and how long a Connect may take — "at least
// 30 seconds" (§5.2); it was 10.
var TCP_BIND_TIMEOUT = 30000;
var TCP_CONNECT_TIMEOUT = 30000;

// In-process deliveries (local relays, relay.local and its replies) are
// asynchronous, as a datagram would be. Rather than one setImmediate and one
// closure per datagram, they wait in one FIFO queue drained by a single
// setImmediate — order is kept. Entries are flat: fn, a, b, c.
var deliverQueue = [];
var deliverScheduled = false;
function deliverLater(fn, a, b, c) {
  deliverQueue.push(fn, a, b, c);
  if (!deliverScheduled) { deliverScheduled = true; setImmediate(drainDeliveries); }
}
function drainDeliveries() {
  deliverScheduled = false;
  var q = deliverQueue;
  deliverQueue = [];
  for (var i = 0; i < q.length; i += 4) {
    try { q[i](q[i + 1], q[i + 2], q[i + 3]); } catch (e) { setImmediate(function() { throw e; }); }
  }
}


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

// Resolve connectDTLS: an injected implementation if one was passed
// (options.connectDTLS / options.lemonTls), otherwise lemon-tls's.
// cb(err, connectDTLS), always asynchronously.
function resolveConnectDTLS(options, cb) {
  if (typeof options.connectDTLS === 'function') return cb(null, options.connectDTLS);
  if (options.lemonTls && typeof options.lemonTls.connectDTLS === 'function') {
    return cb(null, options.lemonTls.connectDTLS);
  }
  queueMicrotask(function () {
    if (typeof lemonTls.connectDTLS !== 'function') return cb(new Error("lemon-tls has no connectDTLS export"));
    cb(null, lemonTls.connectDTLS);
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
    // The buffers of the UDP sockets this Socket binds (udp_buffers.js): a
    // client's transport to its TURN server, and — used on its own — the
    // relay sockets (under a Server, its relay.socketBufferSize, read at each
    // allocation).
    socketBufferSize: checkedSocketBufferSize(options.socketBufferSize, 'socketBufferSize'),

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
      nonceKey: options.nonceKey || null,
      relayIp: options.relayIp || null,
      externalIp: options.externalIp || null,
      portRange: options.portRange || [49152, 65535],
      maxAllocateLifetime: options.maxAllocateLifetime || 3600,
      defaultAllocateLifetime: options.defaultAllocateLifetime || 600,
      secureStun: options.secureStun || false,
      checkOriginConsistency: options.checkOriginConsistency || false,
      allowLoopback: options.allowLoopback || false,
      allowMulticast: options.allowMulticast || false,
      allowPrivatePeers: options.allowPrivatePeers || false,
      isOwnRelayIp: isOwnRelayIp,
      // The nonce scope of the control connection that owns a pending
      // RFC 6062 connection id (see Session valid_control_nonce).
      connectionNonceScope: function(id) {
        var e = tcpRelayConns.get(id);
        if (!e || e.state !== 'pending' || e.owner.destroyed) return null;
        var src = e.owner.session.context.source;
        return src ? src.ip + ':' + src.port : null;
      },
      isSelfServiceIp: typeof options.isSelfServiceIp === 'function' ? options.isSelfServiceIp : null,
      allowedPeers: options.allowedPeers || null,
      deniedPeers: options.deniedPeers || null,
      allowTcpRelay: options.allowTcpRelay || false,
      maxTcpConnectionsPerAllocation: options.maxTcpConnectionsPerAllocation || 8,
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
    tcpPeerConnections: {},  // connectionId → entry (see tcpRelayConns)
    relayIsTcp: false,       // the allocation is RFC 6062 TCP: relaySocket is a net.Server

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

      function onStreamData(chunk) {
        if (context.destroyed) return;
        _tcpChunks.push(chunk);
        _tcpLen += chunk.length;
        parseTcpFrames();
      }
      function onStreamError(err) { ev.emit('error', err); }
      function onStreamClose() { ev.emit('close'); }
      context.transport.on('data', onStreamData);

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
          // That was a ConnectionBind success (RFC 6062 §4.3): from here on
          // the connection carries the peer's bytes, not STUN.
          if (context.detaching) { finishDetach(); return; }
        }
      }

      // Hand the transport over as a raw stream: our listeners off, paused,
      // with the bytes already read past the response put back in front.
      // This Socket is done with it — close() will not touch it.
      function finishDetach() {
        var done = context.detaching;
        context.detaching = null;
        var t = context.transport;
        var rest = _tcpLen > 0 ? compactBuffer().slice(0, _tcpLen) : null;
        _tcpChunks = []; _tcpLen = 0;
        t.removeListener('data', onStreamData);
        t.removeListener('error', onStreamError);
        t.removeListener('close', onStreamClose);
        t.pause();
        if (rest && rest.length) t.unshift(rest);
        context.transport = null;
        context.destroyed = true;
        session.close();
        done(t);
      }

      context.transport.on('error', onStreamError);
      context.transport.on('close', onStreamClose);
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
      // ChannelData is padded to 4 on a stream (RFC 8656 §12.5).
      context.transport.write(toBuffer(wire.pad_channel_data_for_stream(buf)));
    }
  }


  /* ====================== Server-side: Relay socket management ====================== */

  session.on('allocate', function(alloc) {
    if (!context.isServer) return;

    // Mark as handled — prevents session's sync fallback from firing
    alloc._confirmed = true;

    allocateRelayPort(alloc, function(err, relaySocket, address, reservationToken) {
      // The relay port binds asynchronously. If the client went away (closed,
      // TCP reset, idle reap) or the allocation was dropped while the bind was
      // in flight, nobody owns this socket any more: close it and stop. It
      // used to be adopted anyway — the port stayed bound for the life of the
      // process, a localRelays entry pointed at a dead client, and 'allocate'
      // was emitted after 'allocate:expired', so every quota counter above
      // (per-IP, per-user, the application's own) stayed one too high.
      var stale = context.destroyed || session.getAllocation() !== alloc;
      if (err) {
        if (stale) return;
        if (alloc.reject) alloc.reject(err);
        else ev.emit('error', err);
        return;
      }
      if (stale) {
        try { relaySocket.close(); } catch (e) {}
        return;
      }

      // Confirm the allocation with the real relay address — this sends the
      // response to the client (including RESERVATION-TOKEN when port+1 was
      // reserved via EVEN-PORT's R bit). It runs in a dgram bind callback,
      // outside any try/catch of Session's: a throw here (an address that
      // cannot be encoded, say) used to be an uncaught exception that took
      // the whole process down. Now it fails this one allocation.
      try {
        if (alloc.confirm) {
          alloc.confirm(address, reservationToken ? { reservationToken: reservationToken } : null);
        }
      } catch (e) {
        try { relaySocket.close(); } catch (e2) {}
        ev.emit('error', e);
        try { session.dropAllocation(alloc); } catch (e3) {}
        return;
      }

      context.relaySocket = relaySocket;
      context.relayAddress = address;
      context.relayIsTcp = alloc.transport === wire.TRANSPORT.TCP;
      // In-process hand-over is for UDP datagrams; a TCP relay is reached
      // through its listener.
      if (!context.relayIsTcp) localRelays.set(relayKey(address), context);
      addRelayIp(address.ip);

      // Counted from here on: 'allocate:expired' is emitted only for an
      // allocation that was announced with 'allocate', so the two always pair.
      alloc._announced = true;
      ev.emit('allocate', alloc);
    });
  });

  session.on('allocate:expired', function(alloc) {
    // RFC 6062 §5.5: the allocation's data connections go with it.
    closeTcpRelayConnections();
    if (context.relaySocket) {
      if (localRelays.get(relayKey(context.relayAddress)) === context) localRelays.delete(relayKey(context.relayAddress));
      if (context.relayAddress) removeRelayIp(context.relayAddress.ip);
      try { context.relaySocket.close(); } catch (e) {}
      context.relaySocket = null;
      context.relayIsTcp = false;
      context.relayAddress = null;
      context.localReplies = null;
    }
    // An allocation that failed (508) or was dropped before its relay port
    // was bound was never announced — and used to be "expired" anyway, which
    // drove activeAllocations and the per-user/per-IP counts below zero.
    if (!alloc || !alloc._announced) return;
    alloc._announced = false;
    ev.emit('allocate:expired', alloc);
  });

  function allocateRelayPort(alloc, cb) {
    // Read at each allocation (Server passes relayConfig()), so a
    // setConfiguration({ relay }) — the public address discovered a moment
    // after boot, say — reaches clients that connected before it. A copy taken
    // when the client first appeared kept handing them the LAN address.
    var live = typeof context.options.relayConfig === 'function' ? context.options.relayConfig() : null;
    var opt_relay_ip = live ? live.relayIp : context.options.relayIp;
    var opt_external_ip = live ? live.externalIp : context.options.externalIp;
    var opt_port_range = live ? live.portRange : context.options.portRange;
    var buffer_size = live ? live.socketBufferSize : context.socketBufferSize;
    var relay_ip = opt_relay_ip || '0.0.0.0';
    var external_ip = opt_external_ip || relay_ip;

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
    var min_port = opt_port_range ? opt_port_range[0] : 49152;
    var max_port = opt_port_range ? opt_port_range[1] : 65535;

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

    // An IPv6 relay needs an IPv6 address to bind and to announce. With an
    // IPv4 (or unspecified IPv4) relay address every bind failed, and after
    // 100 attempts the client got 508 — RFC 6156 §4.2 says 440.
    if (family === 'udp6' && !(net.isIPv6(relay_ip) && net.isIPv6(external_ip))) {
      var e440 = new Error('Address family not supported (no IPv6 relay address)');
      e440.stunCode = 440;
      return cb(e440);
    }

    // RFC 6062 §5.1: a TCP allocation gets a TCP relayed address, listening.
    // It used to get a UDP port like any other.
    if (alloc.transport === wire.TRANSPORT.TCP) return allocateTcpRelay(relay_ip, external_ip, min_port, max_port, cb);

    // EVEN-PORT (RFC 5766 §14.6): presence requests an even port; the R bit
    // additionally reserves port+1 (claimed later via RESERVATION-TOKEN).
    var need_even = alloc.evenPort != null;
    var need_reserve = !!(alloc.evenPort && (alloc.evenPort === true || alloc.evenPort.reserve));

    // Candidates: every port of the range (only even ones for EVEN-PORT, and
    // with room for port+1 when it is reserved), walked from a random start.
    // It drew 100 random ports instead — the top of the range was never one
    // of them (max_port was excluded), and in a range mostly in use 100
    // draws could all miss the few free ports: 508 with ports still free.
    var first = need_even ? min_port + (min_port % 2) : min_port;
    var last = need_reserve ? max_port - 1 : max_port;
    var step = need_even ? 2 : 1;
    var count = last >= first ? Math.floor((last - first) / step) + 1 : 0;
    var start = Math.floor(Math.random() * count);
    var attempts = 0;
    var max_attempts = Math.min(count, 2000);

    function tryBind() {
      if (attempts >= max_attempts) {
        return cb(new Error('No available relay port in range'));
      }
      var port = first + ((start + attempts) % count) * step;
      attempts++;

      var sock = dgram.createSocket(udpSocketOptions({ type: family }, buffer_size));

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
            var token = random_bytes_sync(8);
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


  // A TCP relayed address: a listener on a free port of the range.
  //
  // It listens with SO_REUSEPORT, so that the connections opened to peers can
  // use the same address (connectFromRelay). That option would also let the
  // listen succeed on a port some other socket with it already holds — a
  // relay of another server process run by the same user — and then the two
  // share incoming connections. So each port is first taken with a plain
  // listen, which fails on any socket already there, and only then reopened
  // with the option. Inside this process tcpRelayPorts keeps them apart.
  function allocateTcpRelay(relay_ip, external_ip, min_port, max_port, cb) {
    var count = max_port >= min_port ? max_port - min_port + 1 : 0;
    var start = Math.floor(Math.random() * count);
    var attempts = 0;
    var max_attempts = Math.min(count, 2000);

    function tryPort() {
      if (attempts >= max_attempts) return cb(new Error('No available relay port in range'));
      var port = min_port + ((start + attempts) % count);
      attempts++;
      if (tcpRelayPorts.has(port)) return tryPort();

      var probe = net.createServer();
      probe.once('error', function() { tryPort(); });
      probe.listen({ host: relay_ip, port: port, exclusive: true }, function() {
        probe.close(function() { listenOn(port, true); });
      });
    }

    function listenOn(port, reusePort) {
      if (tcpRelayPorts.has(port)) return tryPort();   // taken by one of ours meanwhile
      var srv = net.createServer({ pauseOnConnect: true, noDelay: true });
      srv.once('error', function(err) {
        try { srv.close(); } catch (e) {}
        // A platform without SO_REUSEPORT: listen without it. Connections to
        // peers then cannot share the port (see connectFromRelay).
        if (reusePort && err && (err.code === 'ENOTSUP' || err.code === 'EOPNOTSUPP' || err.code === 'EINVAL' ||
                                 err.code === 'ERR_INVALID_ARG_VALUE' || err.code === 'ERR_INVALID_ARG_TYPE')) {
          return listenOn(port, false);
        }
        tryPort();
      });
      var lopts = { host: relay_ip, port: port, exclusive: true };
      if (reusePort) lopts.reusePort = true;
      try { srv.listen(lopts); } catch (e) { if (reusePort) return listenOn(port, false); return tryPort(); }
      srv.once('listening', function() {
        srv.removeAllListeners('error');
        tcpRelayPorts.add(port);
        srv.on('close', function() { tcpRelayPorts.delete(port); });
        srv.on('error', function(err) { ev.emit('error', err); });
        srv.on('connection', onIncomingPeer);
        srv._relayLocal = { ip: relay_ip, port: port, reusePort: reusePort };
        cb(null, srv, { ip: external_ip, port: port });
      });
    }

    tryPort();
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

      // Check permission
      if (!session.hasPermission(rinfo.address)) return;
      var from = null;   // { ip, port } — built only when something needs it

      // Hook: beforeData — peer → client direction. Short-circuit on
      // listenerCount FIRST so the info object isn't allocated per packet when
      // no hook is registered (this is the relay hot path).
      if (ev.listenerCount('beforeData') > 0 && !check_hook_sync('beforeData', {
        peer: from = { ip: rinfo.address, port: rinfo.port },
        source: session.context.source,
        username: session.getAllocation() ? session.getAllocation().username : null,
        size: data.length,
        direction: 'inbound',
      })) return; // silent drop

      // Bandwidth tracking
      session.context.bytesIn += data.length;
      session.context.packetsIn++;

      // Check if there's a channel binding for this peer
      var channel = session.getChannelByPeer(rinfo.address, rinfo.port);
      if (channel !== null) {
        // Send as ChannelData (more efficient). `data` is Buffer from dgram —
        // pass directly, wire.encode_channel_data works on both Buffer and Uint8Array.
        session.sendChannelData(channel, data);
      } else {
        // Send as Data indication
        session.sendData(from || (from = { ip: rinfo.address, port: rinfo.port }), data);
      }

      // Info event: onRelayed (peer → client, inbound). Guard allocation.
      if (ev.listenerCount('onRelayed') > 0) ev.emit('onRelayed', {
        direction: 'inbound',
        peer: from || { ip: rinfo.address, port: rinfo.port },
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

  // Out of this client's relay to a peer: over the network, or — when the peer
  // is another relay of this same process — straight into that relay (see
  // localRelays at the top of the file).
  //
  // Then relay.local (Server option): the application may say a peer address
  // is its own — a WebRTC router on this process's shared port, say. The
  // datagram is handed to it in memory instead of the network, and what it
  // answers comes back in through reply(), into the same 'message' handler a
  // network datagram takes, from the peer's address: permissions, hooks and
  // accounting apply exactly as they would.
  // `cb`, when given, is the send-error callback to reuse (one per channel
  // peer — see the 'data' handler); otherwise one is made for this send.
  function sendFromRelay(peer, out, cb) {
    if (context.relayIsTcp) return;   // a TCP allocation relays over its data connections
    var target = localRelays.size > 0 ? localRelays.get(peer.ip + ':' + peer.port) : undefined;
    if (target && target !== context && target.relaySocket && !target.destroyed && context.relayAddress) {
      var from = context.relayAddress;
      var copy = Buffer.from(out);   // the caller's buffer is not ours to keep past this call
      deliverLater(deliverToRelay, target, copy, {
        address: from.ip, port: from.port, size: copy.length,
        family: from.ip.indexOf(':') >= 0 ? 'IPv6' : 'IPv4',
      });
      return;
    }
    var local = context.options.relayLocal;
    var deliver = local && context.relayAddress ? local(peer.ip, peer.port) : null;
    if (deliver) {
      var relayFrom = context.relayAddress;
      var data = Buffer.from(out);   // the caller's buffer is not ours to keep past this call
      deliverLater(deliverLocal, deliver, data, { from: { ip: relayFrom.ip, port: relayFrom.port }, back: replyFor(peer) });
      return;
    }
    // A peer the policy blocks, allowed only because it is our own relay
    // address (Session.is_blocked_peer): it is reached in memory above or not
    // at all — never through the network, where that address could be some
    // other service on this machine or its LAN.
    if (session.isPolicyBlocked(peer.ip)) return;
    // Nor back into this server's own listeners or relay ports through the
    // network (see Server isSelfService) — a relay of ours was handled above.
    if (context.options.isSelfService && context.options.isSelfService(peer.ip, peer.port)) return;
    context.relaySocket.send(out, 0, out.length, peer.port, peer.ip, cb || function(err) {
      if (err) reportRelaySendError(peer, err);
    });
  }

  function deliverToRelay(target, buf, rinfo) {
    if (!target.relaySocket || target.destroyed) return;
    target.relaySocket.emit('message', buf, rinfo);
  }

  function deliverLocal(deliver, data, d) {
    if (context.destroyed || !context.relaySocket) return;
    deliver(data, d.from, d.back);
  }

  // Send-error callback per channel peer. A channel's peer object is the same
  // on every datagram, so the callback is made once instead of per packet.
  var sendErrCbs = new WeakMap();
  function sendErrFor(peer) {
    var cb = sendErrCbs.get(peer);
    if (!cb) {
      cb = function(err) { if (err) reportRelaySendError(peer, err); };
      sendErrCbs.set(peer, cb);
    }
    return cb;
  }

  // reply(buf) for a peer reached through relay.local: its answer enters this
  // relay as a datagram from that peer. false once the allocation is gone —
  // the caller then forgets it. One per peer, kept while the relay lives.
  function deliverReply(sock, copy, rinfo) {
    if (context.destroyed || context.relaySocket !== sock) return;
    sock.emit('message', copy, rinfo);
  }

  function replyFor(peer) {
    var key = peer.ip + ':' + peer.port;
    var sock = context.relaySocket;
    var r = context.localReplies && context.localReplies.get(key);
    if (r && r.sock === sock) return r.fn;
    var family = peer.ip.indexOf(':') >= 0 ? 'IPv6' : 'IPv4';
    var fn = function (buf) {
      if (context.destroyed || context.relaySocket !== sock) return false;
      var copy = Buffer.from(buf);
      deliverLater(deliverReply, sock, copy, { address: peer.ip, port: peer.port, size: copy.length, family: family });
      return true;
    };
    if (!context.localReplies) context.localReplies = new Map();
    context.localReplies.set(key, { sock: sock, fn: fn });
    return fn;
  }

  // Session 'relay' event: client sent a Send indication → relay to peer
  session.on('relay', function(peer, data) {
    if (!context.relaySocket || context.destroyed) return;

    // HOT PATH: zero-copy Buffer view (was Buffer.from(data) which copied).
    sendFromRelay(peer, toBuffer(data));

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
    sendFromRelay(peer, toBuffer(data), sendErrFor(peer));

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

  // Peer data connections of this Socket's allocation (any state).
  function tcpConnCount() {
    var n = 0;
    for (var k in context.tcpPeerConnections) n++;
    return n;
  }

  function tcpMaxConns() {
    return context.options.maxTcpConnectionsPerAllocation || 8;
  }

  // A peer data connection of this allocation, registered under a new
  // CONNECTION-ID. sock is null while an outgoing connection is still being
  // made (state 'connecting') — it already counts for 446 and the limit.
  function registerTcpConn(peer, sock, state) {
    var alloc = session.getAllocation();
    var entry = {
      id: newConnectionId(),
      peer: peer,
      sock: null,
      state: state,
      owner: context,
      username: alloc ? alloc.username : null,
      realm: session.context.realm || null,
      timer: null,
      dead: false,
    };
    tcpRelayConns.set(entry.id, entry);
    context.tcpPeerConnections[entry.id] = entry;
    if (sock) attachTcpSock(entry, sock);
    return entry;
  }

  function unregisterTcpConn(entry) {
    entry.dead = true;
    if (entry.timer) { clearTimeout(entry.timer); entry.timer = null; }
    if (tcpRelayConns.get(entry.id) === entry) tcpRelayConns.delete(entry.id);
    if (context.tcpPeerConnections[entry.id] === entry) delete context.tcpPeerConnections[entry.id];
  }

  // The connection is up: it waits, unread, for its ConnectionBind — 30 s,
  // then it is closed (RFC 6062 §5.2, §5.3).
  function attachTcpSock(entry, sock) {
    entry.sock = sock;
    entry.state = 'pending';
    sock.on('error', function() {});   // closes; 'close' below cleans up
    sock.on('close', function() { unregisterTcpConn(entry); });
    entry.timer = setTimeout(function() {
      entry.timer = null;
      if (entry.state !== 'bound') sock.destroy();
    }, TCP_BIND_TIMEOUT);
    if (entry.timer.unref) entry.timer.unref();
  }

  function closeTcpRelayConnections() {
    for (var k in context.tcpPeerConnections) {
      var entry = context.tcpPeerConnections[k];
      unregisterTcpConn(entry);
      if (entry.sock) { try { entry.sock.destroy(); } catch (e) {} }
    }
    context.tcpPeerConnections = {};
  }

  // RFC 6062 §5.3: a peer connected to the relayed address. Accepted paused
  // (pauseOnConnect) — what it sends waits in the kernel until the client
  // binds the connection. Closed at once without a permission for the peer.
  function onIncomingPeer(sock) {
    sock.on('error', function() {});
    var peer = { ip: unmapIp(sock.remoteAddress), port: sock.remotePort };
    if (context.destroyed || !context.relayIsTcp || !session.getAllocation() || !peer.ip || !(peer.port > 0)) {
      sock.destroy(); return;
    }
    if (!session.hasPermission(peer.ip)) { sock.destroy(); return; }
    // The per-allocation limit (local policy): nothing is sent to the client.
    if (tcpConnCount() >= tcpMaxConns()) { sock.destroy(); return; }
    sock.setNoDelay(true);
    var entry = registerTcpConn(peer, sock, 'pending');
    try { session.connectionAttempt(peer, entry.id); }
    catch (e) { unregisterTcpConn(entry); sock.destroy(); ev.emit('error', e); }
  }

  // RFC 6062 §5.2 — the Connect checks that need the connections; Session
  // made the rest. cb(err with stunCode) or cb(null, connectionId).
  //
  // It connected with net.connect from any local port — not from the relayed
  // address, which the peer was told about and may only accept connections
  // from — and with a 10 s timeout where the RFC asks at least 30.
  session.on('connect_peer', function(peer, cb) {
    if (context.destroyed || !context.relayIsTcp || !context.relaySocket) { cb(stunError(447)); return; }

    // One connection per peer address, connecting, pending or bound.
    for (var k in context.tcpPeerConnections) {
      var e = context.tcpPeerConnections[k];
      if (e.peer.ip === peer.ip && e.peer.port === peer.port) { cb(stunError(446)); return; }
    }
    if (tcpConnCount() >= tcpMaxConns()) { cb(stunError(403)); return; }
    // Nor into this server's own listeners or relay ports (Server isSelfService).
    if (context.options.isSelfService && context.options.isSelfService(peer.ip, peer.port)) { cb(stunError(403)); return; }

    var entry = registerTcpConn(peer, null, 'connecting');
    connectFromRelay(context.relaySocket._relayLocal, peer, TCP_CONNECT_TIMEOUT, function(err, sock) {
      if (entry.dead || context.destroyed) {   // the allocation went meanwhile
        if (sock) sock.destroy();
        return;
      }
      if (err) {
        unregisterTcpConn(entry);
        cb(stunError(447, err.message));
        return;
      }
      attachTcpSock(entry, sock);
      cb(null, entry.id);
    });
  });

  // RFC 6062 §5.4, on the Socket of the NEW connection the ConnectionBind
  // came on. The id is looked up process-wide. On success the Server (the
  // 'dataConnection' listener) turns this connection into a raw pipe to the
  // peer; without one there is nothing to pipe through, and it is refused.
  session.on('connection_bind', function(connectionId, info, cb) {
    var entry = tcpRelayConns.get(connectionId);
    if (!entry || entry.state !== 'pending' || !entry.sock || entry.owner.destroyed) { cb(stunError(400)); return; }
    // RFC 6062 §4.3: the same credentials as the control connection
    // (RFC 8656 441 Wrong Credentials).
    if ((info.username || null) !== (entry.username || null) || (info.realm || null) !== (entry.realm || null)) {
      cb(stunError(441)); return;
    }
    if (ev.listenerCount('dataConnection') === 0) { cb(stunError(400)); return; }

    entry.state = 'bound';
    if (entry.timer) { clearTimeout(entry.timer); entry.timer = null; }
    cb(null, function() {
      ev.emit('dataConnection', entry.sock, entry.peer);
    });
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
      context.transport = dgram.createSocket(udpSocketOptions({ type: family }, context.socketBufferSize));
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
      // Nagle off, as on the server side: every STUN request and every
      // ChannelData frame is a small write, and one held for the previous
      // one's ACK waits a round trip.
      context.transport.setNoDelay(true);
      // Capture connect-phase errors (ECONNREFUSED, etc.) before bindTransport
      // attaches the persistent handler. Detached above on successful connect.
      context.transport.on('error', _preErr);

    } else if (context.transportType === 'tls') {
      context.transport = lemonTls.connect({
        host: context.serverHost,
        port: context.serverPort,
        servername: options.servername || context.serverHost,
        rejectUnauthorized: options.rejectUnauthorized !== false,
        ca: options.ca || undefined,
        SNICallback: options.SNICallback || undefined,
        // Nagle off on the TCP socket underneath, from its creation (lemon-tls
        // passes net options to net.connect, as node:tls does).
        noDelay: true,
      }, function() {
        if (typeof context.transport.off === 'function') context.transport.off('error', _preErr);
        // Again once connected, for a lemon-tls that does not pass noDelay on:
        // the TLS socket hands it to the TCP socket it now has.
        if (typeof context.transport.setNoDelay === 'function') context.transport.setNoDelay(true);
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
  var method_names = ['binding', 'allocate', 'refresh', 'create_permission', 'channel_bind', 'connect', 'connection_bind'];
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

  // Client-side: RFC 6062 §4.4 — a peer connected to our TCP relayed address.
  // Accept it with acceptConnection(connectionId, cb); left alone, the server
  // closes it after 30 s.
  session.on('connection_attempt', function(peer, connectionId) {
    if (!context.isServer) ev.emit('connectionAttempt', peer, connectionId);
  });

  // Client-side: forward ICMP error notifications from the server
  // (RFC 8656 §11.5 — Data indication with XOR-PEER-ADDRESS + ICMP).
  session.on('icmp', function(peer, icmp) {
    if (!context.isServer) {
      ev.emit('icmp', peer, icmp);
    }
  });


  /* ====================== Client-side: TCP relay (RFC 6062) ====================== */

  // Peers whose Connect failed with 447, and when: the client MUST wait at
  // least 10 s before trying the same peer again (§4.3). And peers with a
  // Connect in flight — two for the same peer MUST NOT be outstanding.
  var _connectFailedAt = {};
  var _connectInFlight = {};
  var CONNECT_RETRY_WAIT = 10000;

  function peerKeyOf(p) { return p.ip + ':' + p.port; }

  // §4.3: Connect on the control connection; with its CONNECTION-ID, a new
  // connection to the server binds it (openDataConnection).
  function connectPeer(peer, cb) {
    cb = cb || function() {};
    if (context.isServer) return cb(new Error('connectPeer is client-side'));
    var p = typeof peer === 'string' ? { ip: peer, port: 0 } : peer;
    var key = peerKeyOf(p);
    if (_connectInFlight[key]) return cb(stunError(446, 'a Connect to this peer is in progress'));
    var failed = _connectFailedAt[key];
    if (failed && Date.now() - failed < CONNECT_RETRY_WAIT) {
      return cb(stunError(447, 'Connect to this peer failed less than 10 s ago (RFC 6062 §4.3)'));
    }

    var tid = null;
    _connectInFlight[key] = true;
    function cleanup() {
      delete _connectInFlight[key];
      session.off('connect:success', onOk);
      session.off('connect:error', onErr);
      session.off('timeout', onTimeout);
    }
    function mine(msg) { return tid && msg && msg.transactionId && Buffer.compare(Buffer.from(msg.transactionId), Buffer.from(tid)) === 0; }
    function onOk(msg) {
      if (!mine(msg)) return;
      cleanup();
      var id = msg.getAttribute(wire.ATTR.CONNECTION_ID);
      if (id === null) return cb(new Error('Connect success without CONNECTION-ID'));
      openDataConnection(id, function(err, stream, info) {
        if (err) return cb(err);
        cb(null, stream, { connectionId: id, peer: p });
      });
    }
    function onErr(msg, err) {
      if (!mine(msg)) return;
      cleanup();
      var code = err && err.code;
      if (code === 447) _connectFailedAt[key] = Date.now();
      cb(stunError(code || 500, 'Connect failed: ' + (code || '?') + (err && err.reason ? ' ' + err.reason : '')));
    }
    function onTimeout() { cleanup(); cb(new Error('Connect timed out')); }
    session.on('connect:success', onOk);
    session.on('connect:error', onErr);
    session.on('timeout', onTimeout);
    session.connect(p, function(e, t) { tid = t; });
  }

  // §4.3/§4.4: a new connection to the same server address, from another
  // local port, authenticated with the same credentials, carrying only a
  // ConnectionBind. On its success the connection is the data connection.
  function openDataConnection(connectionId, cb) {
    cb = cb || function() {};
    if (context.isServer) return cb(new Error('acceptConnection is client-side'));
    if (context.transportType !== 'tcp' && context.transportType !== 'tls') {
      return cb(new Error('RFC 6062 data connections need a TCP or TLS transport'));
    }
    var dopts = {};
    for (var k in options) dopts[k] = options[k];
    dopts.transport = null; dopts.session = null; dopts.send = null;
    dopts.server = context.serverHost; dopts.port = context.serverPort;
    dopts.transportType = context.transportType;
    // The credentials as the control connection uses them now (a realm or
    // password set later with set_context included).
    var sc = session.context;
    if (sc.username) dopts.username = sc.username;
    if (sc.password) dopts.password = sc.password;
    if (sc.authMech) dopts.authMech = sc.authMech;

    var d = new Socket(dopts);
    var ds = d.getSession();
    // The first ConnectionBind goes out authenticated, with the realm and
    // nonce the control connection holds — as coturn's own client does.
    // Unauthenticated, it drew a 401 from coturn, which then closes the
    // connection (a data connection gets one try): our retry never ran.
    // A server that wants a fresh nonce answers 438, and the session retries.
    if (sc.realm) ds.context.realm = sc.realm;
    if (sc.nonce) ds.context.nonce = sc.nonce;
    if (sc.passwordAlgorithm) ds.context.passwordAlgorithm = sc.passwordAlgorithm;
    var settled = false;
    function fin(err, stream) {
      if (settled) return;
      settled = true;
      if (err) { try { d.close(); } catch (e) {} return cb(err); }
      cb(null, stream, { connectionId: connectionId });
    }
    d.on('error', function(err) { fin(err); });
    d.on('close', function() { fin(new Error('data connection closed before ConnectionBind succeeded')); });
    ds.on('connection_bind:success', function() {
      // Detached right after this event, inside the frame loop (finishDetach).
      d._detach(function(stream) { fin(null, stream); });
    });
    ds.on('connection_bind:error', function(msg, err) {
      var code = err && err.code;
      fin(stunError(code || 500, 'ConnectionBind failed: ' + (code || '?') + (err && err.reason ? ' ' + err.reason : '')));
    });
    ds.on('timeout', function() { fin(new Error('ConnectionBind timed out')); });
    d.connect(function() { ds.connectionBind(connectionId); });
  }


  /* ====================== close / destroy ====================== */

  function close() {
    if (context.destroyed) return;
    context.destroyed = true;

    session.close();

    if (context.relaySocket) {
      if (localRelays.get(relayKey(context.relayAddress)) === context) localRelays.delete(relayKey(context.relayAddress));
      if (context.relayAddress) removeRelayIp(context.relayAddress.ip);
      try { context.relaySocket.close(); } catch (e) {}
      context.relaySocket = null;
      context.relayIsTcp = false;
      context.relayAddress = null;
      context.localReplies = null;
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

    // Close TCP relay peer connections (RFC 6062 §5.5 — closing them closes
    // their client data connections too, see Server).
    closeTcpRelayConnections();

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

    // Internal (openDataConnection): hand the TCP/TLS transport over as a raw
    // stream once the response being processed has been taken.
    _detach: function(fn) { context.detaching = fn; },

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

    // RFC 6062 — TCP relay (client-side). Both answer cb(err) or
    // cb(null, stream, info): stream is a duplex byte stream to the peer
    // (a net.Socket, or the TLS socket over TLS), handed over paused — read
    // it with on('data') + resume(), or pipe() it.
    //
    // They used to send the bare requests: Connect and ConnectionBind on the
    // control connection, the second refused by any server following the RFC
    // (and the data was expected as Data indications, which never come).
    connectPeer: connectPeer,
    acceptConnection: openDataConnection,
    connectionBind: openDataConnection,
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