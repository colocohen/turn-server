
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

import * as wire from './wire.js';


function Session(options) {
  if (!(this instanceof Session)) return new Session(options);
  options = options || {};

  var ev = new EventEmitter();

  var context = {
    state: 'new',  // new | ready | closed
    isServer: !!options.isServer,

    software: options.software || null,

    // auth
    authMech: options.authMech || 'none',  // 'none' | 'short-term' | 'long-term' | 'oauth'
    realm: options.realm || null,
    nonce: options.nonce || null,
    nonceExpiry: options.nonceExpiry || 600000,
    nonceCreatedAt: null,
    thirdPartyAuthUrl: options.thirdPartyAuthUrl || null,

    // RFC 8489 §7: FINGERPRINT SHOULD NOT be used over TLS/DTLS
    useFingerprint: options.useFingerprint !== false, // default true, set false for TLS

    // REST API credentials (shared secret mode)
    secret: options.secret || null,
    restCredentialExpiry: options.restCredentialExpiry || 86400, // 24h default

    // static credentials (server)
    credentials: options.credentials || {},

    // client credentials
    username: options.username || null,
    password: options.password || null,

    // client retransmission (RFC 5389 §7.2.1) — set rto for UDP, null for TCP/TLS
    rto: options.rto || null,

    // RFC 8489 — client chosen password algorithm (0x0001=MD5, 0x0002=SHA256)
    passwordAlgorithm: options.passwordAlgorithm || null,

    // source address of the remote side (set by transport layer)
    source: options.source || null,   // { ip, port, family }
    localAddress: options.localAddress || null, // { ip, port } — server listening address

    // server-side relay config
    relayIp: options.relayIp || null,
    externalIp: options.externalIp || null,
    portRange: options.portRange || [49152, 65535],
    maxAllocateLifetime: options.maxAllocateLifetime || 3600,
    defaultAllocateLifetime: options.defaultAllocateLifetime || 600,

    // NAT detection (RFC 5780) — secondary IP/port for CHANGE-REQUEST
    localAddress: options.localAddress || null,  // { ip, port } — primary listening address
    secondaryAddress: options.secondaryAddress || null,  // { ip, port } — alternate IP/port

    // Security — peer address blocking (coturn CVE-2020-26262)
    allowLoopback: !!options.allowLoopback,    // default false
    allowMulticast: !!options.allowMulticast,   // default false
    secureStun: !!options.secureStun,          // require auth for BINDING
    checkOriginConsistency: !!options.checkOriginConsistency,
    _sessionOrigin: null,

    // Bandwidth tracking (built-in counters)
    bytesIn: 0,
    bytesOut: 0,

    // allocation state (one per session / 5-tuple)
    allocation: null,

    // TCP relay connections (RFC 6062)
    tcpConnections: {},
    nextConnectionId: 1,

    lastTransactionId: null,
    lastResponse: null,
  };


  /* ====================== Hook helper ====================== */

  // Synchronous hook pattern. If no listener → default to allowed.
  // Listener calls cb(true/false). Same pattern for all hooks.
  function check_hook(name, info) {
    if (ev.listenerCount(name) === 0) return true;
    var allowed = true;
    ev.emit(name, info, function(result) { allowed = !!result; });
    return allowed;
  }


  /* ====================== Auth helpers ====================== */

  // RFC 8489 §9.2 — structured nonce: timestamp:HMAC(nonceKey, timestamp)
  // Server can validate nonce without storing it. Nonce is stale if timestamp too old.
  var _nonceKey = crypto.randomBytes(16);

  // Source-address binding: include source IP in HMAC so nonce can't be replayed from different 5-tuple
  function _nonce_scope() {
    return context.source ? (context.source.ip + ':' + context.source.port) : '';
  }

  function generate_nonce() {
    var timestamp = Math.floor(Date.now() / 1000).toString(16);
    var mac = crypto.createHmac('sha1', _nonceKey).update(timestamp + _nonce_scope()).digest('hex').slice(0, 16);
    context.nonce = timestamp + ':' + mac;
    context.nonceCreatedAt = Date.now();
    return context.nonce;
  }

  function is_nonce_stale() {
    if (context.nonceCreatedAt === null) return true;
    return (Date.now() - context.nonceCreatedAt) > context.nonceExpiry;
  }

  function validate_nonce(nonce) {
    if (!nonce || nonce.indexOf(':') < 0) return false;
    var parts = nonce.split(':');
    var timestamp = parts[0];
    var mac = parts[1];
    var expected_mac = crypto.createHmac('sha1', _nonceKey).update(timestamp + _nonce_scope()).digest('hex').slice(0, 16);
    if (mac !== expected_mac) return false;
    var nonce_time = parseInt(timestamp, 16) * 1000;
    return (Date.now() - nonce_time) <= context.nonceExpiry;
  }

  // Synchronous callback only. If the 'authenticate' listener calls cb()
  // asynchronously the behavior is undefined. Use synchronous cache/map lookups.
  function get_key_for_user(username, cb) {
    // 1. Static credentials — check first (exact username match)
    if (context.credentials && context.credentials[username] != null) {
      return cb(wire.compute_long_term_key(username, context.realm, context.credentials[username]));
    }

    // 2. REST API credentials: username = "timestamp:userId", password = HMAC(secret, username)
    if (context.secret) {
      var parts = username.split(':');
      if (parts.length >= 2) {
        var timestamp = parseInt(parts[0], 10);
        if (timestamp > 0 && timestamp < Math.floor(Date.now() / 1000)) {
          return cb(null); // expired
        }
      }
      var password = crypto.createHmac('sha1', context.secret).update(username).digest('base64');
      return cb(wire.compute_long_term_key(username, context.realm, password));
    }

    // 3. Dynamic lookup via 'authenticate' event
    if (ev.listenerCount('authenticate') > 0) {
      var called = false;
      ev.emit('authenticate', username, context.realm, function(result) {
        called = true;
        if (result == null || result instanceof Error) return cb(null);
        // result can be a pre-computed HMAC key (Buffer) or a password (string)
        if (typeof result === 'string') return cb(wire.compute_long_term_key(username, context.realm, result));
        cb(result); // assume pre-computed key
      });
      if (!called) cb(null);
      return;
    }

    cb(null); // no credentials found
  }

  function send_challenge(msg) {
    if (context.nonce === null || is_nonce_stale()) generate_nonce();

    var attrs = [
      { type: wire.ATTR.ERROR_CODE, value: { code: 401 } },
      { type: wire.ATTR.REALM, value: context.realm },
      { type: wire.ATTR.NONCE, value: context.nonce },
      // RFC 8489 §9.1 — advertise supported password algorithms
      { type: wire.ATTR.PASSWORD_ALGORITHMS, value: [
        { algorithm: 0x0002, params: new Uint8Array(0) }, // SHA256 preferred
        { algorithm: 0x0001, params: new Uint8Array(0) }, // MD5 fallback
      ] },
    ];

    send_error(msg, 401, attrs, null);
  }

  function send_stale_nonce(msg) {
    generate_nonce();

    send_error(msg, 438, [
      { type: wire.ATTR.ERROR_CODE, value: { code: 438 } },
      { type: wire.ATTR.REALM, value: context.realm },
      { type: wire.ATTR.NONCE, value: context.nonce },
      { type: wire.ATTR.PASSWORD_ALGORITHMS, value: [
        { algorithm: 0x0002, params: new Uint8Array(0) },
        { algorithm: 0x0001, params: new Uint8Array(0) },
      ] },
    ], null);
  }


  /* ====================== Response helpers ====================== */

  // key: HMAC key for MESSAGE-INTEGRITY, or null
  function send_message(method, cls, tid, attributes, key) {
    // FIX: concat instead of push — never mutate caller's array
    var final_attrs = attributes;
    if (context.software && cls !== wire.CLASS.INDICATION) {
      final_attrs = attributes.concat([{ type: wire.ATTR.SOFTWARE, value: context.software }]);
    }

    var result = wire.encode_message({
      method: method,
      cls: cls,
      transactionId: tid,
      attributes: final_attrs,
      key: key || null,
      fingerprint: context.useFingerprint !== false,
    });

    var buf = result.buf;

    // Cache for retransmission detection
    context.lastTransactionId = tid;
    context.lastResponse = buf;

    ev.emit('message', buf);
  }

  function send_success(msg, attributes, key) {
    send_message(msg.method, wire.CLASS.SUCCESS, msg.transactionId, attributes, key);
  }

  function send_error(msg, code, attributes, key) {
    if (!attributes) {
      attributes = [{ type: wire.ATTR.ERROR_CODE, value: { code: code } }];
    }
    send_message(msg.method, wire.CLASS.ERROR, msg.transactionId, attributes, key);
  }

  // Indications: no fingerprint (RFC 5389 — FINGERPRINT is optional, and skipping it
  // avoids CRC32 computation on every relayed data packet. Data indications are the
  // hot path in TURN relay.)
  function send_indication(method, attributes) {
    var result = wire.encode_message({
      method: method,
      cls: wire.CLASS.INDICATION,
      attributes: attributes,
      fingerprint: false,
    });

    ev.emit('message', result.buf);
  }

  // 300 Try Alternate — redirect client to another server
  function send_redirect(msg, alternateServer) {
    send_error(msg, 300, [
      { type: wire.ATTR.ERROR_CODE, value: { code: 300 } },
      { type: wire.ATTR.ALTERNATE_SERVER, value: alternateServer },
    ], null);
  }


  /* ====================== Retransmission detection ====================== */

  function is_retransmission(msg) {
    if (context.lastTransactionId === null) return false;
    var a = context.lastTransactionId, b = msg.transactionId;
    if (a.length !== b.length) return false;
    for (var i = 0; i < 12; i++) { if (a[i] !== b[i]) return false; }
    return true;
  }


  /* ====================== Allocation management ====================== */

  // NOTE: Session picks a placeholder relay port. The Socket layer is responsible
  // for actual port binding and should update via set_context({ relayAddress }).
  function create_allocation(msg, transport, lifetime) {
    var min_port = context.portRange[0];
    var max_port = context.portRange[1];
    var relay_port = min_port + Math.floor(Math.random() * (max_port - min_port));
    var relay_ip = context.externalIp || context.relayIp || '0.0.0.0';
    // When relay IP is unspecified, use a consistent routable address
    if (relay_ip === '0.0.0.0' || relay_ip === '::' || relay_ip === '0:0:0:0:0:0:0:0') {
      if (context.localAddress && context.localAddress.ip && context.localAddress.ip !== '0.0.0.0' && context.localAddress.ip !== '::' &&
          !context.localAddress.ip.startsWith('127.') && context.localAddress.ip !== '::1') {
        relay_ip = context.localAddress.ip;
      }
      // Note: if still 0.0.0.0, Socket.allocateRelayPort resolves it via os.networkInterfaces()
    }

    if (lifetime > context.maxAllocateLifetime) lifetime = context.maxAllocateLifetime;
    if (lifetime < context.defaultAllocateLifetime) lifetime = context.defaultAllocateLifetime;

    var alloc = {
      relayAddress: { ip: relay_ip, port: relay_port },
      lifetime: lifetime,
      expiresAt: Date.now() + (lifetime * 1000),
      transport: transport,
      permissions: {},
      channels: {},
      username: msg.getAttribute(wire.ATTR.USERNAME) || null,
      timer: null,
    };

    alloc.timer = setTimeout(function() {
      expire_allocation();
    }, lifetime * 1000);

    context.allocation = alloc;
    context.state = 'ready';

    return alloc;
  }

  function refresh_allocation(lifetime) {
    var alloc = context.allocation;
    if (!alloc) return;

    if (alloc.timer) clearTimeout(alloc.timer);

    if (lifetime === 0) {
      expire_allocation();
      return;
    }

    if (lifetime > context.maxAllocateLifetime) lifetime = context.maxAllocateLifetime;
    if (lifetime > 0 && lifetime < context.defaultAllocateLifetime) lifetime = context.defaultAllocateLifetime;

    alloc.lifetime = lifetime;
    alloc.expiresAt = Date.now() + (lifetime * 1000);

    alloc.timer = setTimeout(function() {
      expire_allocation();
    }, lifetime * 1000);

    ev.emit('refresh', alloc);
  }

  function expire_allocation() {
    var alloc = context.allocation;
    if (!alloc) return;
    if (alloc.timer) clearTimeout(alloc.timer);
    context.allocation = null;
    context.state = 'new';
    ev.emit('allocate:expired', alloc);
  }

  // CVE-2020-26262 — block dangerous peer addresses by default
  function is_blocked_peer(ip) {
    if (!ip) return true;
    // Loopback
    if (!context.allowLoopback) {
      if (ip === '127.0.0.1' || ip.startsWith('127.') || ip === '::1' || ip === '0:0:0:0:0:0:0:1') return true;
    }
    // Unspecified (0.0.0.0/8, ::/128)
    if (ip === '0.0.0.0' || ip.startsWith('0.') || ip === '::' || ip === '0:0:0:0:0:0:0:0') return true;
    // Multicast
    if (!context.allowMulticast) {
      var first = parseInt(ip.split('.')[0], 10);
      if (first >= 224 && first <= 255) return true; // 224.0.0.0 - 255.255.255.255
      if (ip.toLowerCase().startsWith('ff')) return true; // IPv6 multicast FFxx::
    }
    return false;
  }

  function add_permission(ip) {
    var alloc = context.allocation;
    if (!alloc) return false;
    if (is_blocked_peer(ip)) return false;
    alloc.permissions[ip] = Date.now() + 300000; // 5 minutes
    ev.emit('permission', { ip: ip, allocation: alloc });
    return true;
  }

  function has_permission(ip) {
    var alloc = context.allocation;
    if (!alloc) return false;
    var exp = alloc.permissions[ip];
    if (!exp) return false;
    if (Date.now() > exp) { delete alloc.permissions[ip]; return false; }
    return true;
  }

  function bind_channel(channel_number, peer) {
    var alloc = context.allocation;
    if (!alloc) return false;

    if (channel_number < 0x4000 || channel_number > 0x4FFF) return false;

    // Channel already bound to a different peer?
    var existing = alloc.channels[channel_number];
    if (existing) {
      if (existing.peer.ip !== peer.ip || existing.peer.port !== peer.port) return false;
    }

    // Peer already bound to a different channel?
    var existing_channel = get_channel_by_peer(peer.ip, peer.port);
    if (existing_channel !== null && existing_channel !== channel_number) return false;

    alloc.channels[channel_number] = {
      peer: peer,
      expiresAt: Date.now() + 600000, // 10 minutes
    };

    // Maintain reverse index for O(1) peer→channel lookup
    if (!alloc._peerToChannel) alloc._peerToChannel = {};
    alloc._peerToChannel[peer.ip + ':' + peer.port] = channel_number;

    add_permission(peer.ip);
    ev.emit('channel', { number: channel_number, peer: peer, allocation: alloc });
    return true;
  }

  function get_channel_by_peer(ip, port) {
    var alloc = context.allocation;
    if (!alloc) return null;
    // O(1) lookup via reverse index
    var key = ip + ':' + port;
    var ch_num = alloc._peerToChannel ? alloc._peerToChannel[key] : undefined;
    if (ch_num === undefined) return null;
    var ch = alloc.channels[ch_num];
    if (!ch) { if (alloc._peerToChannel) delete alloc._peerToChannel[key]; return null; }
    if (Date.now() > ch.expiresAt) {
      delete alloc.channels[ch_num];
      if (alloc._peerToChannel) delete alloc._peerToChannel[key];
      return null;
    }
    return ch_num;
  }

  function get_peer_by_channel(channel_number) {
    var alloc = context.allocation;
    if (!alloc) return null;
    var ch = alloc.channels[channel_number];
    if (!ch) return null;
    if (Date.now() > ch.expiresAt) { delete alloc.channels[channel_number]; return null; }
    return ch.peer;
  }


  /* ====================== Message processing ====================== */

  function process_income_message(data) {
    // FIX: wrap in try/catch — malformed messages must not crash
    try {
      if (wire.is_channel_data(data)) {
        process_channel_data(data);
        return;
      }
      if (!wire.is_stun(data)) return;

      var msg = wire.decode_message(data);
      if (msg === null) return;

      ev.emit('raw', msg);

      // Retransmission detection
      if (is_retransmission(msg) && context.lastResponse) {
        ev.emit('message', context.lastResponse);
        return;
      }

      // Fingerprint check
      if (msg.fingerprint_offset !== null) {
        var fp_val = msg.getAttribute(wire.ATTR.FINGERPRINT);
        var before = data.slice(0, msg.fingerprint_offset);
        var expected_fp = wire.compute_fingerprint(before);
        if (fp_val !== expected_fp) return;
      }

      if (context.isServer) {
        process_server_message(msg, data);
      } else {
        process_client_message(msg, data);
      }
    } catch (e) {
      ev.emit('error', e);
    }
  }

  function process_channel_data(data) {
    var parsed = wire.decode_channel_data(data);
    var peer = get_peer_by_channel(parsed.channel);
    if (!peer) return;

    // Hook: beforeRelay — client → peer via ChannelData
    if (context.isServer) {
      if (!check_hook('beforeRelay', {
        username: context.allocation ? context.allocation.username : null,
        source: context.source,
        peer: peer,
        channel: parsed.channel,
        size: parsed.data.length,
        direction: 'outbound',
      })) return;
    }

    context.bytesOut += parsed.data.length;
    ev.emit('data', peer, parsed.data, parsed.channel);
  }


  /* ====================== Server-side processing ====================== */

  // RFC 5389 §7.3.1 — reject requests with unknown comprehension-required attrs
  function check_unknown_comprehension(msg) {
    var unknown = [];
    for (var i = 0; i < msg.attributes.length; i++) {
      var type = msg.attributes[i].type;
      // Comprehension-required range: 0x0000-0x7FFF
      // Skip MESSAGE-INTEGRITY and FINGERPRINT (always handled at protocol level)
      if (type < 0x8000 && type !== wire.ATTR.MESSAGE_INTEGRITY && type !== wire.ATTR.FINGERPRINT) {
        if (!(type in wire.attrs)) {
          unknown.push(type);
        }
      }
    }
    return unknown;
  }

  function process_server_message(msg, raw) {

    // Fingerprint mirroring (coturn behavior, RFC best practice):
    // If client sends FINGERPRINT, server mirrors it in responses for this session.
    // If client does not send FINGERPRINT, server omits it.
    if (msg.cls === wire.CLASS.REQUEST) {
      context.useFingerprint = msg.fingerprint_offset !== null;
    }

    // RFC 5389 §7.3.1 — unknown comprehension-required attrs → 420
    if (msg.cls === wire.CLASS.REQUEST) {
      var unknown = check_unknown_comprehension(msg);
      if (unknown.length > 0) {
        send_error(msg, 420, [
          { type: wire.ATTR.ERROR_CODE, value: { code: 420 } },
          { type: wire.ATTR.UNKNOWN_ATTRIBUTES, value: unknown },
        ], null);
        return;
      }
    }

    // RFC 5389 §7.3.2 — indications with unknown comprehension-required → silent discard
    if (msg.cls === wire.CLASS.INDICATION) {
      var unknown_ind = check_unknown_comprehension(msg);
      if (unknown_ind.length > 0) return;
    }

    // BINDING indication — keep-alive, no response (RFC 5389)
    if (msg.method === wire.METHOD.BINDING && msg.cls === wire.CLASS.INDICATION) {
      return; // silent accept
    }

    // Origin consistency check (coturn --check-origin-consistency)
    if (context.checkOriginConsistency && context.isServer) {
      var origin = msg.getAttribute(wire.ATTR.ORIGIN);
      if (origin) {
        if (context._sessionOrigin === null) { context._sessionOrigin = origin; }
        else if (origin !== context._sessionOrigin) {
          if (msg.cls === wire.CLASS.REQUEST) send_error(msg, 403, null, null);
          return;
        }
      }
    }

    // BINDING request — no auth needed (unless secureStun)
    if (msg.method === wire.METHOD.BINDING && msg.cls === wire.CLASS.REQUEST) {
      if (context.secureStun && context.authMech !== 'none') {
        authenticate_and_handle(msg, raw);
      } else {
        handle_binding(msg);
      }
      return;
    }

    // SEND indication — no auth (but must have allocation)
    if (msg.method === wire.METHOD.SEND && msg.cls === wire.CLASS.INDICATION) {
      handle_send_indication(msg);
      return;
    }

    // Everything else needs auth (if authMech !== 'none')
    if (context.authMech !== 'none' && msg.cls === wire.CLASS.REQUEST) {
      authenticate_and_handle(msg, raw);
      return;
    }

    // No auth mode — route directly
    route_server_request(msg, null);
  }

  function authenticate_and_handle(msg, raw) {
    if (context.authMech === 'long-term') {
      authenticate_long_term(msg, raw);
    } else if (context.authMech === 'short-term') {
      authenticate_short_term(msg, raw);
    } else if (context.authMech === 'oauth') {
      authenticate_oauth(msg, raw);
    }
  }

  // RFC 7635 — OAuth / Third-party auth: ACCESS-TOKEN attribute
  function authenticate_oauth(msg, raw) {
    var token = msg.getAttribute(wire.ATTR.ACCESS_TOKEN);
    if (token === null) {
      // No token — send 401 with THIRD-PARTY-AUTHORIZATION URL if configured
      var attrs = [{ type: wire.ATTR.ERROR_CODE, value: { code: 401 } }];
      if (context.realm) attrs.push({ type: wire.ATTR.REALM, value: context.realm });
      if (context.thirdPartyAuthUrl) {
        attrs.push({ type: wire.ATTR.THIRD_PARTY_AUTHORIZATION, value: context.thirdPartyAuthUrl });
      }
      send_error(msg, 401, attrs, null);
      return;
    }

    // Delegate token validation to 'authenticate_oauth' event
    if (ev.listenerCount('authenticate_oauth') > 0) {
      ev.emit('authenticate_oauth', token, context.realm, function(err, key) {
        if (err || key === null) {
          send_error(msg, 401, null, null);
          return;
        }
        // Validate integrity with the derived key
        if (msg.integrity_offset !== null) {
          var valid = wire.validate_integrity(raw, msg.integrity_offset, key);
          if (!valid) { send_error(msg, 401, null, null); return; }
        }
        route_server_request(msg, key);
      });
    } else {
      // No handler registered
      send_error(msg, 401, null, null);
    }
  }

  // RFC 5389 §10 — Short-term credential: USERNAME + INTEGRITY, no REALM/NONCE
  function authenticate_short_term(msg, raw) {
    var username = msg.getAttribute(wire.ATTR.USERNAME);

    if (username === null || msg.integrity_offset === null) {
      send_error(msg, 400, null, null);
      return;
    }

    // Get password for user
    var password = null;
    if (ev.listenerCount('authenticate') > 0) {
      var called = false;
      ev.emit('authenticate', username, null, function(err, p) {
        called = true;
        if (!err && p != null) password = p;
      });
      if (!called) password = null;
    } else {
      // Look up in credentials map first, then fall back to context.password.
      // ICE connectivity checks use USERNAME = "remoteUfrag:localUfrag" with a
      // single shared password (ice-pwd), so credentials map won't match — the
      // direct password is the expected path for ICE.
      password = context.credentials[username] || context.password || null;
    }

    if (password === null) {
      send_error(msg, 401, null, null);
      return;
    }

    var key = wire.compute_short_term_key(password);
    var valid = wire.validate_integrity(raw, msg.integrity_offset, key);
    if (!valid) {
      send_error(msg, 401, null, null);
      return;
    }

    // Wrong credentials check
    if (context.allocation && context.allocation.username !== null) {
      if (context.allocation.username !== username) {
        send_error(msg, 441, null, key);
        return;
      }
    }

    route_server_request(msg, key);
  }

  // RFC 5389 §11 — Long-term credential: USERNAME + REALM + NONCE + INTEGRITY
  function authenticate_long_term(msg, raw) {
    var username = msg.getAttribute(wire.ATTR.USERNAME);
    var msg_realm = msg.getAttribute(wire.ATTR.REALM);
    var msg_nonce = msg.getAttribute(wire.ATTR.NONCE);

    if (username === null || msg_realm === null || msg_nonce === null) {
      send_challenge(msg);
      return;
    }

    if (!validate_nonce(msg_nonce)) {
      send_stale_nonce(msg);
      return;
    }

    if (msg.integrity_offset === null && msg.integrity_sha256_offset === null) {
      send_challenge(msg);
      return;
    }

    get_key_for_user(username, function(key) {
      if (key === null) {
        send_challenge(msg);
        return;
      }

      // Validate integrity — prefer SHA256 if present, fall back to SHA1
      var valid = false;
      if (msg.integrity_sha256_offset !== null) {
        valid = wire.validate_integrity_sha256(raw, msg.integrity_sha256_offset, key);
      } else if (msg.integrity_offset !== null) {
        valid = wire.validate_integrity(raw, msg.integrity_offset, key);
      }
      if (!valid) {
        send_challenge(msg);
        return;
      }

      // RFC 8489 §9.2.1 — bid-down attack prevention
      // If server advertised PASSWORD-ALGORITHMS, client SHOULD include PASSWORD-ALGORITHM
      // If client uses SHA1 but SHA256 was offered, SHOULD reject
      var client_algo = msg.getAttribute(wire.ATTR.PASSWORD_ALGORITHM);
      if (msg.integrity_sha256_offset === null && msg.integrity_offset !== null) {
        // Client used SHA1 — check if we offered SHA256
        if (client_algo && client_algo.algorithm !== 0x0001) {
          // Mismatch: client claims one algo but used another
          send_error(msg, 400, null, null);
          return;
        }
      }

      // Wrong credentials check
      if (context.allocation && context.allocation.username !== null) {
        if (context.allocation.username !== username) {
          send_error(msg, 441, null, key);
          return;
        }
      }

      route_server_request(msg, key);
    });
  }

  function route_server_request(msg, key) {
    // Hook: authorize — called after auth, before executing any method
    var username = msg.getAttribute(wire.ATTR.USERNAME);
    if (!check_hook('authorize', {
      method: msg.method,
      methodName: wire.METHOD_NAME[msg.method] || null,
      username: username,
      source: context.source,
    })) {
      send_error(msg, 403, null, key); // Forbidden
      return;
    }

    switch (msg.method) {
      case wire.METHOD.BINDING:           handle_binding(msg); break;
      case wire.METHOD.ALLOCATE:          handle_allocate(msg, key); break;
      case wire.METHOD.REFRESH:           handle_refresh(msg, key); break;
      case wire.METHOD.CREATE_PERMISSION: handle_create_permission(msg, key); break;
      case wire.METHOD.CHANNEL_BIND:      handle_channel_bind(msg, key); break;
      case wire.METHOD.CONNECT:           handle_connect(msg, key); break;
      case wire.METHOD.CONNECTION_BIND:   handle_connection_bind(msg, key); break;
      default: send_error(msg, 400, null, key); break;
    }
  }


  /* ====================== Server handlers ====================== */

  function handle_binding(msg) {
    if (context.source === null) { send_error(msg, 400, null, null); return; }

    var response_attrs = [
      { type: wire.ATTR.XOR_MAPPED_ADDRESS, value: context.source },
    ];

    // RFC 5780 — RESPONSE-ORIGIN: address the response is sent from
    if (context.localAddress) {
      response_attrs.push({ type: wire.ATTR.RESPONSE_ORIGIN, value: context.localAddress });
    }

    // RFC 5780 — OTHER-ADDRESS: the secondary address for NAT tests
    if (context.secondaryAddress) {
      response_attrs.push({ type: wire.ATTR.OTHER_ADDRESS, value: context.secondaryAddress });
    }

    // RFC 5780 — CHANGE-REQUEST: client asks response from different IP/port
    var change = msg.getAttribute(wire.ATTR.CHANGE_REQUEST);
    if (change) {
      // Emit 'change_request' — Socket layer must send the response from the alternate address
      ev.emit('change_request', msg, change, response_attrs);
      return; // Socket layer sends the response
    }

    send_success(msg, response_attrs, null);
  }

  function handle_allocate(msg, key) {
    if (context.allocation !== null) {
      send_error(msg, 437, null, key);
      return;
    }

    var transport = msg.getAttribute(wire.ATTR.REQUESTED_TRANSPORT);
    if (transport === null) { send_error(msg, 400, null, key); return; }
    // RFC 5766: UDP (17) required. RFC 6062: TCP (6) also allowed for TCP relay.
    if (transport !== wire.TRANSPORT.UDP && transport !== wire.TRANSPORT.TCP) {
      send_error(msg, 442, null, key); return;
    }

    // RESERVATION-TOKEN and EVEN-PORT together is invalid
    var reservation_token = msg.getAttribute(wire.ATTR.RESERVATION_TOKEN);
    var even_port = msg.getAttribute(wire.ATTR.EVEN_PORT);
    if (reservation_token !== null && even_port !== null) {
      send_error(msg, 400, null, key);
      return;
    }

    // RFC 6156 — REQUESTED-ADDRESS-FAMILY (0x0017)
    var requested_family = msg.getAttribute(wire.ATTR.REQUESTED_ADDRESS_FAMILY);
    if (requested_family !== null && requested_family !== wire.FAMILY.IPV4 && requested_family !== wire.FAMILY.IPV6) {
      send_error(msg, 440, null, key); // Address Family not Supported
      return;
    }

    // Quota check via synchronous event
    var username = msg.getAttribute(wire.ATTR.USERNAME);
    if (ev.listenerCount('quota') > 0) {
      var allowed = true;
      ev.emit('quota', username, function(result) { allowed = result; });
      if (!allowed) { send_error(msg, 486, null, key); return; }
    }

    var lifetime = msg.getAttribute(wire.ATTR.LIFETIME);
    if (lifetime === null) lifetime = context.defaultAllocateLifetime;

    // Hook: beforeAllocate — can inspect/modify allocation params or reject
    var alloc_info = {
      username: username,
      source: context.source,
      transport: transport,
      lifetime: lifetime,
      requestedFamily: requested_family,
      evenPort: even_port,
      reservationToken: reservation_token,
      dontFragment: msg.getAttribute(wire.ATTR.DONT_FRAGMENT) || false,
    };

    if (!check_hook('beforeAllocate', alloc_info)) {
      send_error(msg, 403, null, key);
      return;
    }

    // Hook may have modified lifetime
    lifetime = alloc_info.lifetime;

    var alloc = create_allocation(msg, transport, lifetime);

    // Store flags for Socket layer
    alloc.evenPort = even_port;
    alloc.reservationToken = reservation_token;
    alloc.dontFragment = msg.getAttribute(wire.ATTR.DONT_FRAGMENT) || false;
    alloc.requestedFamily = requested_family;

    // RFC 8656 — ADDITIONAL-ADDRESS-FAMILY for dual-stack allocation
    var additional_family = msg.getAttribute(wire.ATTR.ADDITIONAL_ADDRESS_FAMILY);
    if (additional_family !== null) {
      if (additional_family !== wire.FAMILY.IPV4 && additional_family !== wire.FAMILY.IPV6) {
        additional_family = null;
      } else if (additional_family === requested_family || (requested_family === null && additional_family === wire.FAMILY.IPV4)) {
        additional_family = null;
      }
    }
    alloc.additionalFamily = additional_family;

    // Deferred response: Socket needs to bind relay port first, then call alloc.confirm(addr)
    // If nobody calls confirm synchronously during the 'allocate' event, send response immediately
    alloc._confirmed = false;
    alloc._responseSent = false;

    alloc.confirm = function(addr) {
      if (alloc._responseSent) return; // guard against double-confirm
      alloc._responseSent = true;
      alloc._confirmed = true;
      alloc.relayAddress = addr;
      var success_attrs = [
        { type: wire.ATTR.XOR_RELAYED_ADDRESS, value: alloc.relayAddress },
        { type: wire.ATTR.XOR_MAPPED_ADDRESS, value: context.source },
        { type: wire.ATTR.LIFETIME, value: alloc.lifetime },
      ];
      send_success(msg, success_attrs, key);
    };

    alloc.reject = function(err) {
      if (alloc._responseSent) return;
      alloc._responseSent = true;
      alloc._confirmed = true;
      expire_allocation();
      send_error(msg, 508, null, key); // Insufficient Capacity
    };

    // Emit allocate event — Socket.js calls alloc.confirm(addr) asynchronously
    // If no Socket layer (standalone session), confirm immediately with the placeholder address
    ev.emit('allocate', alloc);
    if (!alloc._confirmed) {
      alloc.confirm(alloc.relayAddress);
    }
  }

  function handle_refresh(msg, key) {
    if (context.allocation === null) { send_error(msg, 437, null, key); return; }

    var lifetime = msg.getAttribute(wire.ATTR.LIFETIME);
    if (lifetime === null) lifetime = context.allocation.lifetime;

    // Hook: beforeRefresh — can modify lifetime or reject
    var refresh_info = {
      username: context.allocation.username,
      source: context.source,
      lifetime: lifetime,
      currentLifetime: context.allocation.lifetime,
    };

    if (!check_hook('beforeRefresh', refresh_info)) {
      send_error(msg, 403, null, key);
      return;
    }

    // Hook may have modified lifetime
    lifetime = refresh_info.lifetime;

    refresh_allocation(lifetime);

    send_success(msg, [
      { type: wire.ATTR.LIFETIME, value: lifetime === 0 ? 0 : context.allocation ? context.allocation.lifetime : 0 },
    ], key);
  }

  function handle_create_permission(msg, key) {
    if (context.allocation === null) { send_error(msg, 437, null, key); return; }

    var peers = [];
    for (var i = 0; i < msg.attributes.length; i++) {
      if (msg.attributes[i].type === wire.ATTR.XOR_PEER_ADDRESS) {
        peers.push(msg.attributes[i].value);
      }
    }
    if (peers.length === 0) { send_error(msg, 400, null, key); return; }

    // Hook: beforePermission — check each peer
    for (var j = 0; j < peers.length; j++) {
      if (!check_hook('beforePermission', {
        username: context.allocation.username,
        source: context.source,
        peer: peers[j],
      })) {
        send_error(msg, 403, null, key);
        return;
      }
    }

    for (var k = 0; k < peers.length; k++) add_permission(peers[k].ip);

    send_success(msg, [], key);
  }

  function handle_channel_bind(msg, key) {
    if (context.allocation === null) { send_error(msg, 437, null, key); return; }

    var channel_number = msg.getAttribute(wire.ATTR.CHANNEL_NUMBER);
    var peer = msg.getAttribute(wire.ATTR.XOR_PEER_ADDRESS);

    if (channel_number === null || peer === null) { send_error(msg, 400, null, key); return; }
    if (channel_number < 0x4000 || channel_number > 0x4FFF) { send_error(msg, 400, null, key); return; }

    // Hook: beforeChannelBind
    if (!check_hook('beforeChannelBind', {
      username: context.allocation.username,
      source: context.source,
      channel: channel_number,
      peer: peer,
    })) {
      send_error(msg, 403, null, key);
      return;
    }

    var ok = bind_channel(channel_number, peer);
    if (!ok) { send_error(msg, 400, null, key); return; }

    send_success(msg, [], key);
  }

  function handle_send_indication(msg) {
    if (context.allocation === null) return;
    var peer = msg.getAttribute(wire.ATTR.XOR_PEER_ADDRESS);
    var data = msg.getAttribute(wire.ATTR.DATA);
    if (peer === null || data === null) return;
    if (!has_permission(peer.ip)) return;

    // Hook: beforeRelay — client → peer direction
    if (!check_hook('beforeRelay', {
      username: context.allocation.username,
      source: context.source,
      peer: peer,
      size: data.length,
      direction: 'outbound',
    })) return; // silent drop

    context.bytesOut += data.length;
    ev.emit('relay', peer, data);
  }


  /* ====================== TCP relay — RFC 6062 ====================== */

  function handle_connect(msg, key) {
    // Must have allocation with TCP transport
    if (context.allocation === null) { send_error(msg, 437, null, key); return; }

    var peer = msg.getAttribute(wire.ATTR.XOR_PEER_ADDRESS);
    if (peer === null) { send_error(msg, 400, null, key); return; }

    // Must have permission for this peer
    if (!has_permission(peer.ip)) {
      send_error(msg, 403, null, key);
      return;
    }

    // Check if connection to this peer already exists
    var conn_keys = Object.keys(context.tcpConnections);
    for (var i = 0; i < conn_keys.length; i++) {
      var existing = context.tcpConnections[conn_keys[i]];
      if (existing.peer.ip === peer.ip && existing.peer.port === peer.port) {
        send_error(msg, 446, null, key); // Connection Already Exists
        return;
      }
    }

    // Hook: beforeConnect
    if (!check_hook('beforeConnect', {
      username: context.allocation.username,
      source: context.source,
      peer: peer,
    })) {
      send_error(msg, 403, null, key);
      return;
    }

    // Assign connection ID
    var connectionId = context.nextConnectionId++;

    context.tcpConnections[connectionId] = {
      peer: peer,
      state: 'pending',
    };

    // Emit 'connect_peer' — Socket layer opens the actual TCP connection
    ev.emit('connect_peer', connectionId, peer, function(err) {
      if (err) {
        delete context.tcpConnections[connectionId];
        send_error(msg, 447, null, key); // Connection Timeout or Failure
        return;
      }

      context.tcpConnections[connectionId].state = 'established';

      send_success(msg, [
        { type: wire.ATTR.CONNECTION_ID, value: connectionId },
      ], key);

      // Send ConnectionAttempt indication to client
      send_indication(wire.METHOD.CONNECTION_ATTEMPT, [
        { type: wire.ATTR.XOR_PEER_ADDRESS, value: peer },
        { type: wire.ATTR.CONNECTION_ID, value: connectionId },
      ]);
    });
  }

  function handle_connection_bind(msg, key) {
    var connectionId = msg.getAttribute(wire.ATTR.CONNECTION_ID);
    if (connectionId === null) { send_error(msg, 400, null, key); return; }

    var conn = context.tcpConnections[connectionId];
    if (!conn || conn.state !== 'established') {
      send_error(msg, 400, null, key);
      return;
    }

    // Emit 'connection_bind' — Socket layer binds this TCP stream to the peer connection
    ev.emit('connection_bind', connectionId, conn.peer, function(err) {
      if (err) {
        send_error(msg, 400, null, key);
        return;
      }
      send_success(msg, [], key);
    });
  }


  /* ====================== Client-side processing ====================== */

  // Pending request tracking for auto-retry on 401/438
  var _pendingRequest = null; // { method, attributes, retries }
  var _pendingTransactionId = null; // 12-byte Uint8Array

  function process_client_message(msg) {
    // RFC 8489 §6.3.3: client MUST verify transactionId matches pending request
    if (_pendingTransactionId !== null && msg.transactionId) {
      var match = true;
      for (var ti = 0; ti < 12; ti++) {
        if (msg.transactionId[ti] !== _pendingTransactionId[ti]) { match = false; break; }
      }
      if (!match) return; // silently discard unmatched response
    }

    if (msg.cls === wire.CLASS.SUCCESS) {
      _pendingRequest = null;
      _pendingTransactionId = null;
      stop_retransmission();
      ev.emit('success', msg);
      ev.emit((wire.METHOD_NAME[msg.method] || 'unknown') + ':success', msg);
      return;
    }

    if (msg.cls === wire.CLASS.ERROR) {
      var err = msg.getAttribute(wire.ATTR.ERROR_CODE);

      // 300 Try Alternate — emit redirect event with alternate server info
      if (err && err.code === 300) {
        var alt_server = msg.getAttribute(wire.ATTR.ALTERNATE_SERVER);
        var alt_domain = msg.getAttribute(wire.ATTR.ALTERNATE_DOMAIN);
        _pendingRequest = null;
        _pendingTransactionId = null;
        stop_retransmission();
        ev.emit('redirect', { server: alt_server, domain: alt_domain });
        return;
      }

      // Auto-retry on 401 Unauthorized — extract realm+nonce and resend
      if (err && err.code === 401 && _pendingRequest && _pendingRequest.retries < 1) {
        var new_realm = msg.getAttribute(wire.ATTR.REALM);
        var new_nonce = msg.getAttribute(wire.ATTR.NONCE);
        if (new_realm && new_nonce && context.username && context.password) {
          context.realm = new_realm;
          context.nonce = new_nonce;
          _clientKeyInputs = null; // invalidate key cache

          // RFC 8489 §9.2.1 — bid-down prevention: extract PASSWORD-ALGORITHMS
          var pw_algos = msg.getAttribute(wire.ATTR.PASSWORD_ALGORITHMS);
          if (pw_algos && pw_algos.length > 0) {
            // Prefer SHA256 (0x0002) over MD5 (0x0001)
            for (var pa = 0; pa < pw_algos.length; pa++) {
              if (pw_algos[pa].algorithm === 0x0002) { context.passwordAlgorithm = 0x0002; break; }
            }
            if (!context.passwordAlgorithm) context.passwordAlgorithm = pw_algos[0].algorithm;
          }

          _pendingRequest.retries++;
          send_client_request(_pendingRequest.method, _pendingRequest.attributes);
          return;
        }
      }

      // Auto-retry on 438 Stale Nonce — extract new nonce and resend
      if (err && err.code === 438 && _pendingRequest && _pendingRequest.retries < 1) {
        var stale_nonce = msg.getAttribute(wire.ATTR.NONCE);
        if (stale_nonce) {
          context.nonce = stale_nonce;
          _pendingRequest.retries++;
          send_client_request(_pendingRequest.method, _pendingRequest.attributes);
          return;
        }
      }

      _pendingRequest = null;
      _pendingTransactionId = null;
      stop_retransmission();
      ev.emit('error_response', msg, err);
      ev.emit((wire.METHOD_NAME[msg.method] || 'unknown') + ':error', msg, err);
      return;
    }

    if (msg.method === wire.METHOD.DATA && msg.cls === wire.CLASS.INDICATION) {
      var peer = msg.getAttribute(wire.ATTR.XOR_PEER_ADDRESS);
      var data = msg.getAttribute(wire.ATTR.DATA);
      if (peer && data) ev.emit('data', peer, data, null);
    }
  }


  /* ====================== Client-side send helpers ====================== */

  // Cached client key — invalidated when username/realm/password change in set_context
  var _clientKey = null;
  var _clientKeyInputs = null; // 'user:realm:pass' to detect changes

  function get_client_key() {
    if (context.authMech === 'long-term' && context.username && context.realm && context.password) {
      var inputs = context.username + ':' + context.realm + ':' + context.password;
      if (_clientKeyInputs !== inputs) {
        _clientKey = wire.compute_long_term_key(context.username, context.realm, context.password);
        _clientKeyInputs = inputs;
      }
      return _clientKey;
    }
    if (context.authMech === 'short-term' && context.password) {
      return wire.compute_short_term_key(context.password);
    }
    return null;
  }

  // RFC 8489 §6.2.1 — UDP: retransmission with exponential backoff
  // RFC 8489 §6.2.2 — TCP: transaction timeout Ti (default 39.5s)
  var _rtoTimer = null;
  var _rtoAttempt = 0;
  var _rtoLastBuf = null;
  var _rtoMaxRetries = 7;
  var _rtoBase = context.rto || null;
  var _tcpTimeout = options.tcpTimeout || 39500; // Ti = 39.5s default

  function start_retransmission(buf) {
    stop_retransmission();
    if (_rtoBase !== null) {
      // UDP mode: exponential backoff retransmission
      _rtoLastBuf = buf;
      _rtoAttempt = 0;
      schedule_retransmit();
    } else {
      // TCP mode: single timeout (Ti)
      _rtoTimer = setTimeout(function() {
        _rtoTimer = null;
        _pendingRequest = null;
        _pendingTransactionId = null;
        ev.emit('timeout');
      }, _tcpTimeout);
    }
    _rtoLastBuf = buf;
    _rtoAttempt = 0;
    schedule_retransmit();
  }

  function schedule_retransmit() {
    if (_rtoAttempt >= _rtoMaxRetries) {
      // Timeout — no response
      stop_retransmission();
      ev.emit('timeout');
      return;
    }
    var delay = _rtoBase * Math.pow(2, _rtoAttempt);
    if (delay > 16 * _rtoBase) delay = 16 * _rtoBase; // Rm cap
    _rtoTimer = setTimeout(function() {
      _rtoAttempt++;
      ev.emit('message', _rtoLastBuf); // resend
      schedule_retransmit();
    }, delay);
  }

  function stop_retransmission() {
    if (_rtoTimer) { clearTimeout(_rtoTimer); _rtoTimer = null; }
    _rtoLastBuf = null;
    _rtoAttempt = 0;
  }

  function send_client_request(method, attributes, cb) {
    // Save for auto-retry on 401/438 (base attributes, before auth)
    if (!_pendingRequest || _pendingRequest.method !== method) {
      _pendingRequest = { method: method, attributes: attributes, retries: 0 };
    }

    // Build auth attributes
    var final_attrs = attributes;
    if (context.authMech === 'long-term' && context.username && context.realm && context.nonce) {
      final_attrs = attributes.concat([
        { type: wire.ATTR.USERNAME, value: context.username },
        { type: wire.ATTR.REALM, value: context.realm },
        { type: wire.ATTR.NONCE, value: context.nonce },
      ]);
    } else if (context.authMech === 'short-term' && context.username) {
      final_attrs = attributes.concat([
        { type: wire.ATTR.USERNAME, value: context.username },
      ]);
    }

    // Client may echo PASSWORD-ALGORITHM to indicate chosen algo
    if (context.authMech === 'long-term' && context.passwordAlgorithm) {
      final_attrs = final_attrs.concat([
        { type: wire.ATTR.PASSWORD_ALGORITHM, value: { algorithm: context.passwordAlgorithm, params: new Uint8Array(0) } },
      ]);
    }

    if (context.software) {
      final_attrs = final_attrs.concat([{ type: wire.ATTR.SOFTWARE, value: context.software }]);
    }

    var result = wire.encode_message({
      method: method,
      cls: wire.CLASS.REQUEST,
      attributes: final_attrs,
      key: get_client_key(),
      fingerprint: context.useFingerprint !== false,
    });

    ev.emit('message', result.buf);
    _pendingTransactionId = result.transactionId;
    start_retransmission(result.buf);
    if (cb) cb(null, result.transactionId);
  }


  /* ====================== set_context ====================== */

  function set_context(options) {
    var has_changed = false;

    if (options && typeof options === 'object') {

      if ('source' in options) {
        if (options.source !== context.source) {
          context.source = options.source;
          has_changed = true;
        }
      }

      if ('realm' in options) {
        if (options.realm !== context.realm) {
          context.realm = options.realm;
          has_changed = true;
        }
      }

      if ('nonce' in options) {
        if (options.nonce !== context.nonce) {
          context.nonce = options.nonce;
          has_changed = true;
        }
      }

      if ('username' in options) {
        if (options.username !== context.username) {
          context.username = options.username;
          has_changed = true;
        }
      }

      if ('password' in options) {
        if (options.password !== context.password) {
          context.password = options.password;
          has_changed = true;
        }
      }

      if ('authMech' in options) {
        if (options.authMech !== context.authMech) {
          context.authMech = options.authMech;
          has_changed = true;
        }
      }

      if ('secret' in options) {
        if (options.secret !== context.secret) {
          context.secret = options.secret;
          has_changed = true;
        }
      }

      if ('software' in options) {
        if (options.software !== context.software) {
          context.software = options.software;
          has_changed = true;
        }
      }

      if ('relayIp' in options) {
        if (options.relayIp !== context.relayIp) {
          context.relayIp = options.relayIp;
          has_changed = true;
        }
      }

      if ('externalIp' in options) {
        if (options.externalIp !== context.externalIp) {
          context.externalIp = options.externalIp;
          has_changed = true;
        }
      }

      if ('credentials' in options) {
        context.credentials = options.credentials;
        has_changed = true;
      }

      // Allow Socket layer to update relay address after real port binding
      if ('relayAddress' in options && context.allocation) {
        context.allocation.relayAddress = options.relayAddress;
        has_changed = true;
      }
    }

    if (has_changed) ev.emit('contextChanged', context);
  }


  /* ====================== Client auto-refresh ====================== */

  var _refreshTimer = null;
  var _permissionTimers = {};  // ip → timer
  var _channelTimers = {};     // channel → timer
  var _autoRefresh = false;

  function enable_auto_refresh() {
    _autoRefresh = true;
  }

  // Schedule allocation refresh (lifetime - 60s margin, minimum 30s)
  function schedule_allocation_refresh(lifetime) {
    if (!_autoRefresh || context.isServer) return;
    if (_refreshTimer) clearTimeout(_refreshTimer);
    var delay = Math.max((lifetime - 60) * 1000, 30000);
    _refreshTimer = setTimeout(function() {
      if (context.state === 'closed') return;
      send_client_request(wire.METHOD.REFRESH, [
        { type: wire.ATTR.LIFETIME, value: lifetime },
      ]);
      // Re-schedule on success (handled by allocate:success)
    }, delay);
  }

  // Schedule permission refresh (every 4 min, expires at 5)
  function schedule_permission_refresh(peers) {
    if (!_autoRefresh || context.isServer) return;
    var key = peers.map(function(p) { return p.ip || p; }).join(',');
    if (_permissionTimers[key]) clearTimeout(_permissionTimers[key]);
    _permissionTimers[key] = setTimeout(function() {
      if (context.state === 'closed') return;
      var attrs = [];
      for (var i = 0; i < peers.length; i++) {
        var p = typeof peers[i] === 'string' ? { ip: peers[i], port: 0 } : peers[i];
        attrs.push({ type: wire.ATTR.XOR_PEER_ADDRESS, value: p });
      }
      send_client_request(wire.METHOD.CREATE_PERMISSION, attrs);
    }, 240000); // 4 minutes
  }

  // Schedule channel rebind (every 9 min, expires at 10)
  function schedule_channel_refresh(channel, peer) {
    if (!_autoRefresh || context.isServer) return;
    if (_channelTimers[channel]) clearTimeout(_channelTimers[channel]);
    _channelTimers[channel] = setTimeout(function() {
      if (context.state === 'closed') return;
      var p = typeof peer === 'string' ? { ip: peer, port: 0 } : peer;
      send_client_request(wire.METHOD.CHANNEL_BIND, [
        { type: wire.ATTR.CHANNEL_NUMBER, value: channel },
        { type: wire.ATTR.XOR_PEER_ADDRESS, value: p },
      ]);
    }, 540000); // 9 minutes
  }

  function clear_refresh_timers() {
    if (_refreshTimer) { clearTimeout(_refreshTimer); _refreshTimer = null; }
    var pk = Object.keys(_permissionTimers);
    for (var i = 0; i < pk.length; i++) clearTimeout(_permissionTimers[pk[i]]);
    _permissionTimers = {};
    var ck = Object.keys(_channelTimers);
    for (var j = 0; j < ck.length; j++) clearTimeout(_channelTimers[ck[j]]);
    _channelTimers = {};
  }

  // Hook into success events for auto-scheduling
  if (!context.isServer) {
    ev.on('allocate:success', function(msg) {
      var lt = msg.getAttribute(wire.ATTR.LIFETIME);
      if (lt && _autoRefresh) schedule_allocation_refresh(lt);
    });
    ev.on('refresh:success', function(msg) {
      var lt = msg.getAttribute(wire.ATTR.LIFETIME);
      if (lt && lt > 0 && _autoRefresh) schedule_allocation_refresh(lt);
    });
    ev.on('create_permission:success', function() {
      // Re-schedule handled by caller via schedule_permission_refresh
    });
    ev.on('channel_bind:success', function() {
      // Re-schedule handled by caller via schedule_channel_refresh
    });
  }


  /* ====================== close ====================== */

  function close() {
    stop_retransmission();
    clear_refresh_timers();
    if (context.allocation) expire_allocation();
    context.state = 'closed';
    ev.emit('close');
  }


  /* ====================== API ====================== */

  var api = {
    context: context,
    isServer: context.isServer,

    on:  function(name, fn) { ev.on(name, fn); },
    off: function(name, fn) { ev.off(name, fn); },

    message: process_income_message,
    set_context: set_context,
    close: close,

    addUser: function(u, p) { context.credentials[u] = p; },
    removeUser: function(u) { delete context.credentials[u]; },

    // Server-side
    sendData: function(peer, data) {
      send_indication(wire.METHOD.DATA, [
        { type: wire.ATTR.XOR_PEER_ADDRESS, value: peer },
        { type: wire.ATTR.DATA, value: data },
      ]);
    },
    sendChannelData: function(channel_number, data) {
      ev.emit('message', wire.encode_channel_data(channel_number, data));
    },

    hasPermission: has_permission,
    getPeerByChannel: get_peer_by_channel,
    getChannelByPeer: function(ip, port) { return get_channel_by_peer(ip, port); },
    getAllocation: function() { return context.allocation; },
    getBandwidth: function() { return { bytesIn: context.bytesIn, bytesOut: context.bytesOut }; },

    /** Send 300 Try Alternate to redirect client */
    redirect: function(msg, alternateServer) { send_redirect(msg, alternateServer); },

    /** Check if a peer IP is blocked by security policy */
    isBlockedPeer: function(ip) { return is_blocked_peer(ip); },

    // Client-side
    binding: function(attrs, cb) {
      if (typeof attrs === 'function') { cb = attrs; attrs = []; }
      send_client_request(wire.METHOD.BINDING, attrs || [], cb);
    },
    allocate: function(options, cb) {
      options = options || {};
      var a = [{ type: wire.ATTR.REQUESTED_TRANSPORT, value: options.transport || wire.TRANSPORT.UDP }];
      if (options.lifetime) a.push({ type: wire.ATTR.LIFETIME, value: options.lifetime });
      if (options.dontFragment) a.push({ type: wire.ATTR.DONT_FRAGMENT, value: true });
      send_client_request(wire.METHOD.ALLOCATE, a, cb);
    },
    refresh: function(lifetime, cb) {
      var a = [];
      if (typeof lifetime === 'number') a.push({ type: wire.ATTR.LIFETIME, value: lifetime });
      send_client_request(wire.METHOD.REFRESH, a, cb);
    },
    createPermission: function(peers, cb) {
      if (!Array.isArray(peers)) peers = [peers];
      var a = [];
      for (var i = 0; i < peers.length; i++) {
        var p = typeof peers[i] === 'string' ? { ip: peers[i], port: 0 } : peers[i];
        a.push({ type: wire.ATTR.XOR_PEER_ADDRESS, value: p });
      }
      send_client_request(wire.METHOD.CREATE_PERMISSION, a, cb);
    },
    channelBind: function(channel_number, peer, cb) {
      var p = typeof peer === 'string' ? { ip: peer, port: 0 } : peer;
      send_client_request(wire.METHOD.CHANNEL_BIND, [
        { type: wire.ATTR.CHANNEL_NUMBER, value: channel_number },
        { type: wire.ATTR.XOR_PEER_ADDRESS, value: p },
      ], cb);
    },
    send: function(peer, data) {
      var p = typeof peer === 'string' ? { ip: peer, port: 0 } : peer;
      send_indication(wire.METHOD.SEND, [
        { type: wire.ATTR.XOR_PEER_ADDRESS, value: p },
        { type: wire.ATTR.DATA, value: data },
      ]);
    },

    // RFC 6062 — TCP relay
    connect: function(peer, cb) {
      var p = typeof peer === 'string' ? { ip: peer, port: 0 } : peer;
      send_client_request(wire.METHOD.CONNECT, [
        { type: wire.ATTR.XOR_PEER_ADDRESS, value: p },
      ], cb);
    },
    connectionBind: function(connectionId, cb) {
      send_client_request(wire.METHOD.CONNECTION_BIND, [
        { type: wire.ATTR.CONNECTION_ID, value: connectionId },
      ], cb);
    },

    /** Enable auto-refresh for allocations (lifetime-60s), permissions (4min), channels (9min) */
    enableAutoRefresh: function() { enable_auto_refresh(); },

    /** Schedule permission refresh (call after createPermission success) */
    schedulePermissionRefresh: function(peers) { schedule_permission_refresh(peers); },

    /** Schedule channel refresh (call after channelBind success) */
    scheduleChannelRefresh: function(channel, peer) { schedule_channel_refresh(channel, peer); },
  };

  for (var k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) this[k] = api[k];
  }

  return this;
}

export default Session;
