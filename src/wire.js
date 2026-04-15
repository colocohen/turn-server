
import crypto from 'node:crypto';

/* ================================ Constants ================================ */

var _te = new TextEncoder();
var _td = new TextDecoder();

var MAGIC_COOKIE = 0x2112A442;
var MAGIC_COOKIE_BUF = new Uint8Array([0x21, 0x12, 0xA4, 0x42]);
var HEADER_SIZE = 20;

var CLASS = {
  REQUEST: 0x0000, INDICATION: 0x0010, SUCCESS: 0x0100, ERROR: 0x0110,
};

var ATTR = {
  MAPPED_ADDRESS: 0x0001, USERNAME: 0x0006, MESSAGE_INTEGRITY: 0x0008,
  ERROR_CODE: 0x0009, UNKNOWN_ATTRIBUTES: 0x000A, REALM: 0x0014,
  NONCE: 0x0015, XOR_MAPPED_ADDRESS: 0x0020,
  CHANNEL_NUMBER: 0x000C, LIFETIME: 0x000D, XOR_PEER_ADDRESS: 0x0012,
  DATA: 0x0013, XOR_RELAYED_ADDRESS: 0x0016, EVEN_PORT: 0x0018,
  REQUESTED_TRANSPORT: 0x0019, DONT_FRAGMENT: 0x001A, RESERVATION_TOKEN: 0x0022,
  REQUESTED_ADDRESS_FAMILY: 0x0017,

  // RFC 8489 (STUN-bis)
  MESSAGE_INTEGRITY_SHA256: 0x001C,
  PASSWORD_ALGORITHM:       0x001D,
  USERHASH:                 0x001E,
  PASSWORD_ALGORITHMS:      0x8002,

  // RFC 6062 (TCP relay)
  CONNECTION_ID: 0x002A,

  // RFC 5780 (NAT detection)
  CHANGE_REQUEST:  0x0003,
  PADDING:         0x0026,
  RESPONSE_PORT:   0x0027,
  RESPONSE_ORIGIN: 0x802B,
  OTHER_ADDRESS:   0x802C,

  // RFC 8656 (TURN-bis)
  ADDITIONAL_ADDRESS_FAMILY: 0x8000,
  ADDRESS_ERROR_CODE:        0x8001,
  ICMP:                      0x8004,

  // RFC 5245 (ICE)
  PRIORITY:        0x0024,
  USE_CANDIDATE:   0x0025,
  ICE_CONTROLLED:  0x8029,
  ICE_CONTROLLING: 0x802A,

  // RFC 7635 (Third-party / OAuth)
  ACCESS_TOKEN:               0x001B,
  THIRD_PARTY_AUTHORIZATION:  0x802E,

  // RFC 8489 (STUN-bis extras)
  ALTERNATE_DOMAIN: 0x8003,

  // RFC 5780 (NAT detection extras)
  CACHE_TIMEOUT: 0x8027,

  // RFC 7982 (retransmission counting)
  TRANSACTION_TRANSMIT_COUNTER: 0x8025,

  // RFC 6679 (ECN)
  ECN_CHECK: 0x802D,

  // RFC 8016 (Mobility)
  MOBILITY_TICKET: 0x8030,

  // Multi-tenant TURN (draft-ietf-tram-stun-origin)
  ORIGIN: 0x802F,

  // Meta (RFC pending)
  META_DTLS_IN_STUN:     0xC070,
  META_DTLS_IN_STUN_ACK: 0xC071,

  // Cisco
  CISCO_STUN_FLOWDATA:  0xC000,
  CISCO_WEBEX_FLOW_INFO: 0xC003,

  // Location-aware / Odin (Cisco-related)
  ENF_FLOW_DESCRIPTION: 0xC001,
  ENF_NETWORK_STATUS:   0xC002,

  // Citrix
  CITRIX_TRANSACTION_ID: 0xC056,

  // Google
  GOOG_NETWORK_INFO:              0xC057,
  GOOG_LAST_ICE_CHECK_RECEIVED:   0xC058,
  GOOG_MISC_INFO:                 0xC059,
  GOOG_OBSOLETE_1:                0xC05A,
  GOOG_CONNECTION_ID:             0xC05B,
  GOOG_DELTA:                     0xC05C,
  GOOG_DELTA_ACK:                 0xC05D,
  GOOG_DELTA_SYNC_REQ:            0xC05E,
  GOOG_MESSAGE_INTEGRITY_32:      0xC060,

  SOFTWARE: 0x8022, ALTERNATE_SERVER: 0x8023, FINGERPRINT: 0x8028,
};

var METHOD = {
  BINDING: 0x0001, ALLOCATE: 0x0003, REFRESH: 0x0004,
  SEND: 0x0006, DATA: 0x0007, CREATE_PERMISSION: 0x0008, CHANNEL_BIND: 0x0009,
  // RFC 6062 — TCP relay
  CONNECT: 0x000A, CONNECTION_BIND: 0x000B, CONNECTION_ATTEMPT: 0x000C,
  // Google extension
  GOOG_PING: 0x080,
};

var ERROR_CODE = {
  TRY_ALTERNATE: 300, BAD_REQUEST: 400, UNAUTHORIZED: 401, FORBIDDEN: 403,
  UNKNOWN_ATTRIBUTE: 420, ALLOCATION_MISMATCH: 437, STALE_NONCE: 438,
  ADDRESS_FAMILY_NOT_SUPPORTED: 440, WRONG_CREDENTIALS: 441,
  UNSUPPORTED_TRANSPORT: 442, PEER_ADDRESS_FAMILY_MISMATCH: 443,
  ALLOCATION_QUOTA: 486, SERVER_ERROR: 500, INSUFFICIENT_CAPACITY: 508,
  // RFC 6062
  CONNECTION_ALREADY_EXISTS: 446, CONNECTION_TIMEOUT_OR_FAILURE: 447,
  // RFC 5245 (ICE)
  ROLE_CONFLICT: 487,
  // RFC 8016 (Mobility)
  MOBILITY_FORBIDDEN: 405,
};

var ERROR_REASON = {};
ERROR_REASON[300] = 'Try Alternate';       ERROR_REASON[400] = 'Bad Request';
ERROR_REASON[401] = 'Unauthorized';        ERROR_REASON[403] = 'Forbidden';
ERROR_REASON[420] = 'Unknown Attribute';   ERROR_REASON[437] = 'Allocation Mismatch';
ERROR_REASON[438] = 'Stale Nonce';         ERROR_REASON[440] = 'Address Family not Supported';
ERROR_REASON[441] = 'Wrong Credentials';   ERROR_REASON[442] = 'Unsupported Transport Protocol';
ERROR_REASON[486] = 'Allocation Quota Reached';
ERROR_REASON[500] = 'Server Error';        ERROR_REASON[508] = 'Insufficient Capacity';
ERROR_REASON[443] = 'Peer Address Family Mismatch';
ERROR_REASON[446] = 'Connection Already Exists';
ERROR_REASON[447] = 'Connection Timeout or Failure';
ERROR_REASON[487] = 'Role Conflict';
ERROR_REASON[405] = 'Mobility Forbidden';

var TRANSPORT = { UDP: 17, TCP: 6 };
var FAMILY = { IPV4: 0x01, IPV6: 0x02 };

var METHOD_NAME = {};
METHOD_NAME[0x0001] = 'binding';    METHOD_NAME[0x0003] = 'allocate';
METHOD_NAME[0x0004] = 'refresh';    METHOD_NAME[0x0006] = 'send';
METHOD_NAME[0x0007] = 'data';       METHOD_NAME[0x0008] = 'create_permission';
METHOD_NAME[0x0009] = 'channel_bind';
METHOD_NAME[0x000A] = 'connect';    METHOD_NAME[0x000B] = 'connection_bind';
METHOD_NAME[0x000C] = 'connection_attempt';
METHOD_NAME[0x0080] = 'goog_ping';

var CLASS_NAME = {};
CLASS_NAME[0x0000] = 'request';  CLASS_NAME[0x0010] = 'indication';
CLASS_NAME[0x0100] = 'success';  CLASS_NAME[0x0110] = 'error';


/* ========================= Binary helpers ================================= */

function w_u8(buf, off, v)  { buf[off++] = v & 0xFF; return off; }
function w_u16(buf, off, v) { buf[off++] = (v >>> 8) & 0xFF; buf[off++] = v & 0xFF; return off; }
function w_u32(buf, off, v) { buf[off++] = (v >>> 24) & 0xFF; buf[off++] = (v >>> 16) & 0xFF; buf[off++] = (v >>> 8) & 0xFF; buf[off++] = v & 0xFF; return off; }
function w_bytes(buf, off, b) { buf.set(b, off); return off + b.length; }

function r_u8(buf, off)  { return [buf[off++] >>> 0, off]; }
function r_u16(buf, off) { return [((buf[off] << 8) | buf[off + 1]) >>> 0, off + 2]; }
function r_u32(buf, off) { return [((buf[off] << 24) | (buf[off+1] << 16) | (buf[off+2] << 8) | buf[off+3]) >>> 0, off + 4]; }
function r_bytes(buf, off, n) { return [buf.slice(off, off + n), off + n]; }


/* ============================ Address helpers ============================== */

function parse_ipv4(str) {
  var parts = str.split('.');
  var out = new Uint8Array(4);
  for (var i = 0; i < 4; i++) out[i] = parseInt(parts[i], 10) & 0xFF;
  return out;
}

function format_ipv4(buf) {
  return buf[0] + '.' + buf[1] + '.' + buf[2] + '.' + buf[3];
}

function parse_ipv6(str) {
  var halves = str.split('::');
  var left = halves[0] ? halves[0].split(':') : [];
  var right = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  var missing = 8 - left.length - right.length;
  var groups = [];
  for (var i = 0; i < left.length; i++) groups.push(left[i]);
  for (var j = 0; j < missing; j++) groups.push('0');
  for (var k = 0; k < right.length; k++) groups.push(right[k]);
  var out = new Uint8Array(16);
  for (var g = 0; g < 8; g++) {
    var val = parseInt(groups[g] || '0', 16);
    out[g * 2] = (val >>> 8) & 0xFF;
    out[g * 2 + 1] = val & 0xFF;
  }
  return out;
}

function format_ipv6(buf) {
  var groups = [];
  for (var i = 0; i < 16; i += 2) groups.push(((buf[i] << 8) | buf[i + 1]));

  // RFC 5952: find longest run of consecutive zero groups for :: compression
  var best_start = -1, best_len = 0, cur_start = -1, cur_len = 0;
  for (var j = 0; j < 8; j++) {
    if (groups[j] === 0) {
      if (cur_start < 0) cur_start = j;
      cur_len++;
      if (cur_len > best_len) { best_start = cur_start; best_len = cur_len; }
    } else {
      cur_start = -1; cur_len = 0;
    }
  }

  if (best_len < 2) {
    // No compression
    return groups.map(function(g) { return g.toString(16); }).join(':');
  }

  var parts = [];
  for (var k = 0; k < 8; k++) {
    if (k === best_start) { parts.push(''); if (k === 0) parts.push(''); continue; }
    if (k > best_start && k < best_start + best_len) continue;
    parts.push(groups[k].toString(16));
  }
  if (best_start + best_len === 8) parts.push('');
  return parts.join(':');
}

function detect_family(ip) { return ip.indexOf(':') >= 0 ? FAMILY.IPV6 : FAMILY.IPV4; }


/* ========================== Message type encoding ========================== */

function encode_type(method, cls) {
  var m = method & 0xFFF; var c = cls & 0x110;
  var c0 = (c >> 4) & 1; var c1 = (c >> 8) & 1;
  return ((m & 0x0F80) << 2) | (c1 << 8) | ((m & 0x0070) << 1) | (c0 << 4) | (m & 0x000F);
}

function decode_type(type) {
  var c0 = (type >> 4) & 1; var c1 = (type >> 8) & 1;
  return { method: ((type & 0x3E00) >> 2) | ((type & 0x00E0) >> 1) | (type & 0x000F), cls: (c1 << 8) | (c0 << 4) };
}


/* ======================== Attribute encode/decode ========================== */

var attrs = {};

// ---- address helpers (shared by MAPPED, XOR-MAPPED, XOR-PEER, XOR-RELAYED, ALTERNATE) ----

function encode_address(value, xor_port, xor_ip, xor_ip6_extra) {
  var family = value.family || detect_family(value.ip);
  var port = (value.port || 0) ^ xor_port;

  if (family === FAMILY.IPV4) {
    var ip = parse_ipv4(value.ip);
    if (xor_ip) { for (var i = 0; i < 4; i++) ip[i] ^= xor_ip[i]; }
    var out = new Uint8Array(8);
    out[1] = FAMILY.IPV4;
    w_u16(out, 2, port);
    w_bytes(out, 4, ip);
    return out;
  }

  var ip6 = parse_ipv6(value.ip);
  if (xor_ip) { for (var j = 0; j < 4; j++) ip6[j] ^= xor_ip[j]; }
  if (xor_ip6_extra) { for (var k = 0; k < 12; k++) ip6[4 + k] ^= xor_ip6_extra[k]; }
  var out6 = new Uint8Array(20);
  out6[1] = FAMILY.IPV6;
  w_u16(out6, 2, port);
  w_bytes(out6, 4, ip6);
  return out6;
}

function decode_address(data, xor_port, xor_ip, xor_ip6_extra) {
  var off = 0;
  var reserved; [reserved, off] = r_u8(data, off);
  var family;   [family, off] = r_u8(data, off);
  var port;     [port, off] = r_u16(data, off);
  port ^= xor_port;

  if (family === FAMILY.IPV4) {
    var addr; [addr, off] = r_bytes(data, off, 4);
    if (xor_ip) { for (var i = 0; i < 4; i++) addr[i] ^= xor_ip[i]; }
    return { family: FAMILY.IPV4, ip: format_ipv4(addr), port: port };
  }

  var addr6; [addr6, off] = r_bytes(data, off, 16);
  if (xor_ip) { for (var j = 0; j < 4; j++) addr6[j] ^= xor_ip[j]; }
  if (xor_ip6_extra) { for (var k = 0; k < 12; k++) addr6[4 + k] ^= xor_ip6_extra[k]; }
  return { family: FAMILY.IPV6, ip: format_ipv6(addr6), port: port };
}

attrs[ATTR.MAPPED_ADDRESS] = {
  encode: function(v) { return encode_address(v, 0, null, null); },
  decode: function(d) { return decode_address(d, 0, null, null); }
};

attrs[ATTR.XOR_MAPPED_ADDRESS] = {
  encode: function(v, tid) { return encode_address(v, 0x2112, MAGIC_COOKIE_BUF, tid); },
  decode: function(d, tid) { return decode_address(d, 0x2112, MAGIC_COOKIE_BUF, tid); }
};

attrs[ATTR.FINGERPRINT] = {
  encode: function(v) { var o = new Uint8Array(4); w_u32(o, 0, v); return o; },
  decode: function(d) { return r_u32(d, 0)[0]; }
};

attrs[ATTR.XOR_PEER_ADDRESS]    = attrs[ATTR.XOR_MAPPED_ADDRESS];
attrs[ATTR.XOR_RELAYED_ADDRESS] = attrs[ATTR.XOR_MAPPED_ADDRESS];
attrs[ATTR.ALTERNATE_SERVER]    = attrs[ATTR.MAPPED_ADDRESS];

// RFC 8489 byte limits: USERNAME <513, REALM <763, NONCE <763, SOFTWARE <763
function make_str_codec(max_bytes) {
  return {
    encode: function(v) {
      var bytes = typeof v === 'string' ? _te.encode(v) : v;
      if (max_bytes && bytes.length > max_bytes) bytes = bytes.slice(0, max_bytes);
      return bytes;
    },
    decode: function(d) { return _td.decode(d); }
  };
}

attrs[ATTR.USERNAME] = make_str_codec(513);
attrs[ATTR.REALM]    = make_str_codec(763);
attrs[ATTR.NONCE]    = make_str_codec(763);
attrs[ATTR.SOFTWARE] = make_str_codec(763);

attrs[ATTR.ERROR_CODE] = {
  encode: function(value) {
    var code = value.code || value;
    // RFC 5389 §15.6: error code MUST be in range 300-699
    if (code < 300 || code > 699) code = 500;
    var reason = value.reason || ERROR_REASON[code] || '';
    var rb = _te.encode(reason);
    if (rb.length > 763) rb = rb.slice(0, 763);
    var out = new Uint8Array(4 + rb.length);
    w_u16(out, 0, 0);
    w_u8(out, 2, Math.floor(code / 100) & 0x07);
    w_u8(out, 3, code % 100);
    w_bytes(out, 4, rb);
    return out;
  },
  decode: function(data) {
    var cls; [cls] = r_u8(data, 2);
    var num; [num] = r_u8(data, 3);
    var code = (cls & 0x07) * 100 + num;
    var reason = data.length > 4 ? _td.decode(data.slice(4)) : '';
    return { code: code, reason: reason };
  }
};

attrs[ATTR.UNKNOWN_ATTRIBUTES] = {
  encode: function(v) { var o = new Uint8Array(v.length * 2); for (var i = 0; i < v.length; i++) w_u16(o, i * 2, v[i]); return o; },
  decode: function(d) { var o = [], off = 0; while (off + 2 <= d.length) { var v; [v, off] = r_u16(d, off); o.push(v); } return o; }
};

attrs[ATTR.CHANNEL_NUMBER] = {
  encode: function(v) { var o = new Uint8Array(4); w_u16(o, 0, v); return o; },
  decode: function(d) { return r_u16(d, 0)[0]; }
};

attrs[ATTR.LIFETIME] = {
  encode: function(v) { var o = new Uint8Array(4); w_u32(o, 0, v); return o; },
  decode: function(d) { return r_u32(d, 0)[0]; }
};

attrs[ATTR.REQUESTED_TRANSPORT] = {
  encode: function(v) { var o = new Uint8Array(4); o[0] = v; return o; },
  decode: function(d) { return d[0]; }
};

attrs[ATTR.EVEN_PORT] = {
  encode: function(v) { return new Uint8Array([v ? 0x80 : 0x00]); },
  decode: function(d) { return (d[0] & 0x80) !== 0; }
};

attrs[ATTR.RESERVATION_TOKEN] = {
  encode: function(v) { var o = new Uint8Array(8); w_bytes(o, 0, v); return o; },
  decode: function(d) { return d.slice(0, 8); }
};

attrs[ATTR.DONT_FRAGMENT] = {
  encode: function() { return new Uint8Array(0); },
  decode: function() { return true; }
};

// RFC 6156 — 1 byte family + 3 bytes RFFU
attrs[ATTR.REQUESTED_ADDRESS_FAMILY] = {
  encode: function(v) { var o = new Uint8Array(4); o[0] = v; return o; },
  decode: function(d) { return d[0]; }
};

attrs[ATTR.DATA] = {
  encode: function(v) { return v instanceof Uint8Array ? v : new Uint8Array(v); },
  decode: function(d) { return d.slice(0); } // explicit copy — caller may store this
};

// RFC 5245 — ICE attributes
attrs[ATTR.PRIORITY] = {
  encode: function(v) { var o = new Uint8Array(4); w_u32(o, 0, v); return o; },
  decode: function(d) { return r_u32(d, 0)[0]; }
};

attrs[ATTR.USE_CANDIDATE] = {
  encode: function() { return new Uint8Array(0); },
  decode: function() { return true; }
};

// ICE-CONTROLLED / ICE-CONTROLLING — 64-bit tiebreaker
attrs[ATTR.ICE_CONTROLLED] = {
  encode: function(v) {
    if (v instanceof Uint8Array) return v;
    var o = new Uint8Array(8);
    if (typeof v === 'bigint') {
      var dv = new DataView(o.buffer); dv.setBigUint64(0, v);
    } else if (Array.isArray(v)) { w_u32(o, 0, v[0]); w_u32(o, 4, v[1]); }
    else { w_u32(o, 0, 0); w_u32(o, 4, v >>> 0); }
    return o;
  },
  decode: function(d) {
    var raw = d.slice(0, 8);
    var dv = new DataView(raw.buffer, raw.byteOffset, 8);
    return { raw: raw, value: dv.getBigUint64(0) };
  }
};
attrs[ATTR.ICE_CONTROLLING] = attrs[ATTR.ICE_CONTROLLED];

// draft-ietf-tram-stun-origin — ORIGIN (string, like a URL origin)
attrs[ATTR.ORIGIN] = make_str_codec(763);

// RFC 8656 — ICMP attribute (type(2) + code(2) + data(4))
attrs[ATTR.ICMP] = {
  encode: function(v) {
    var o = new Uint8Array(8);
    w_u16(o, 0, v.type || 0);
    w_u16(o, 2, v.code || 0);
    w_u32(o, 4, v.data || 0);
    return o;
  },
  decode: function(d) {
    return { type: r_u16(d, 0)[0], code: r_u16(d, 2)[0], data: r_u32(d, 4)[0] };
  }
};

// RFC 7635 — ACCESS-TOKEN (variable-length opaque)
attrs[ATTR.ACCESS_TOKEN] = {
  encode: function(v) { return v instanceof Uint8Array ? v : _te.encode(v); },
  decode: function(d) { return d.slice(0); }
};

// RFC 7635 — THIRD-PARTY-AUTHORIZATION (URL string)
attrs[ATTR.THIRD_PARTY_AUTHORIZATION] = make_str_codec(763);

// RFC 8489 — ALTERNATE-DOMAIN (string)
attrs[ATTR.ALTERNATE_DOMAIN] = make_str_codec(255);

// RFC 5780 — CACHE-TIMEOUT (uint32, seconds)
attrs[ATTR.CACHE_TIMEOUT] = {
  encode: function(v) { var o = new Uint8Array(4); w_u32(o, 0, v); return o; },
  decode: function(d) { return r_u32(d, 0)[0]; }
};

// RFC 7982 — TRANSACTION-TRANSMIT-COUNTER (uint16 req + uint16 resp)
attrs[ATTR.TRANSACTION_TRANSMIT_COUNTER] = {
  encode: function(v) {
    var o = new Uint8Array(4);
    w_u16(o, 0, v.req || v[0] || 0);
    w_u16(o, 2, v.resp || v[1] || 0);
    return o;
  },
  decode: function(d) {
    return { req: r_u16(d, 0)[0], resp: r_u16(d, 2)[0] };
  }
};

// RFC 6679 — ECN-CHECK (valid bit + val bit + padding, 4 bytes)
attrs[ATTR.ECN_CHECK] = {
  encode: function(v) {
    var o = new Uint8Array(4);
    var flags = 0;
    if (v.valid) flags |= 0x80;
    if (v.val) flags |= 0x40;
    w_u8(o, 0, flags);
    return o;
  },
  decode: function(d) {
    return { valid: !!(d[0] & 0x80), val: !!(d[0] & 0x40) };
  }
};

// RFC 8016 — MOBILITY-TICKET (variable-length opaque, encrypted by server)
attrs[ATTR.MOBILITY_TICKET] = {
  encode: function(v) { return v instanceof Uint8Array ? v : new Uint8Array(v); },
  decode: function(d) { return d.slice(0); }
};

// RFC 8489 — USERHASH (32 bytes, SHA256(username:realm))
attrs[ATTR.USERHASH] = {
  encode: function(v) { return v instanceof Uint8Array ? v : new Uint8Array(v); },
  decode: function(d) { return d.slice(0); }
};


/* ==================== Vendor extension codecs ============================ */

// Generic opaque codec for vendor attributes — pass-through raw bytes
var _opaque_codec = {
  encode: function(v) { return v instanceof Uint8Array ? v : new Uint8Array(v); },
  decode: function(d) { return d.slice(0); }
};

// Meta (Facebook/WhatsApp)
attrs[ATTR.META_DTLS_IN_STUN]     = _opaque_codec;
attrs[ATTR.META_DTLS_IN_STUN_ACK] = _opaque_codec;

// Cisco
attrs[ATTR.CISCO_STUN_FLOWDATA]   = _opaque_codec;
attrs[ATTR.CISCO_WEBEX_FLOW_INFO] = _opaque_codec;

// Odin / ENF
attrs[ATTR.ENF_FLOW_DESCRIPTION]  = _opaque_codec;
attrs[ATTR.ENF_NETWORK_STATUS]    = _opaque_codec;

// Citrix
attrs[ATTR.CITRIX_TRANSACTION_ID] = _opaque_codec;

// Google
attrs[ATTR.GOOG_NETWORK_INFO]            = _opaque_codec;
attrs[ATTR.GOOG_LAST_ICE_CHECK_RECEIVED] = _opaque_codec;
attrs[ATTR.GOOG_MISC_INFO]               = _opaque_codec;
attrs[ATTR.GOOG_OBSOLETE_1]              = _opaque_codec;
attrs[ATTR.GOOG_CONNECTION_ID]           = _opaque_codec;
attrs[ATTR.GOOG_DELTA]                   = _opaque_codec;
attrs[ATTR.GOOG_DELTA_ACK]               = _opaque_codec;
attrs[ATTR.GOOG_DELTA_SYNC_REQ]          = _opaque_codec;

// Google — 4-byte truncated message integrity
attrs[ATTR.GOOG_MESSAGE_INTEGRITY_32] = {
  encode: function(v) { return v instanceof Uint8Array ? v : new Uint8Array(v); },
  decode: function(d) { return d.slice(0, 4); }
};

attrs[ATTR.MESSAGE_INTEGRITY] = {
  encode: function(v) { return v instanceof Uint8Array ? v : new Uint8Array(v); },
  decode: function(d) { return d.slice(0); }
};

// RFC 8489 — MESSAGE-INTEGRITY-SHA256 (variable length, up to 32 bytes)
attrs[ATTR.MESSAGE_INTEGRITY_SHA256] = {
  encode: function(v) { return v instanceof Uint8Array ? v : new Uint8Array(v); },
  decode: function(d) { return d.slice(0); }
};

// RFC 6062 — CONNECTION-ID (4 bytes)
attrs[ATTR.CONNECTION_ID] = {
  encode: function(v) { var o = new Uint8Array(4); w_u32(o, 0, v); return o; },
  decode: function(d) { return r_u32(d, 0)[0]; }
};

// RFC 5780 — CHANGE-REQUEST (4 bytes, bit flags)
attrs[ATTR.CHANGE_REQUEST] = {
  encode: function(v) {
    var flags = 0;
    if (v.changeIp) flags |= 0x04;
    if (v.changePort) flags |= 0x02;
    var o = new Uint8Array(4);
    w_u32(o, 0, flags);
    return o;
  },
  decode: function(d) {
    var flags = r_u32(d, 0)[0];
    return { changeIp: !!(flags & 0x04), changePort: !!(flags & 0x02) };
  }
};

// RFC 5780 — RESPONSE-ORIGIN, OTHER-ADDRESS (same as MAPPED-ADDRESS)
attrs[ATTR.RESPONSE_ORIGIN] = attrs[ATTR.MAPPED_ADDRESS];
attrs[ATTR.OTHER_ADDRESS]   = attrs[ATTR.MAPPED_ADDRESS];

// RFC 5780 — PADDING (arbitrary bytes)
attrs[ATTR.PADDING] = {
  encode: function(v) {
    if (typeof v === 'number') return new Uint8Array(v); // pad to N bytes
    return v instanceof Uint8Array ? v : new Uint8Array(v);
  },
  decode: function(d) { return d.slice(0); }
};

// RFC 5780 — RESPONSE-PORT (2 bytes + 2 RFFU)
attrs[ATTR.RESPONSE_PORT] = {
  encode: function(v) { var o = new Uint8Array(4); w_u16(o, 0, v); return o; },
  decode: function(d) { return r_u16(d, 0)[0]; }
};

// RFC 8656 — ADDITIONAL-ADDRESS-FAMILY (same format as REQUESTED-ADDRESS-FAMILY)
attrs[ATTR.ADDITIONAL_ADDRESS_FAMILY] = attrs[ATTR.REQUESTED_ADDRESS_FAMILY];

// RFC 8656 — ADDRESS-ERROR-CODE (family + error code)
attrs[ATTR.ADDRESS_ERROR_CODE] = {
  encode: function(v) {
    var out = new Uint8Array(8);
    w_u8(out, 0, v.family || 0);
    // bytes 1-2: reserved
    w_u8(out, 3, Math.floor(v.code / 100) & 0x07);
    w_u8(out, 4, v.code % 100);
    if (v.reason) {
      var rb = _te.encode(v.reason);
      var out2 = new Uint8Array(5 + rb.length);
      out2.set(out.subarray(0, 5), 0);
      out2.set(rb, 5);
      return out2;
    }
    return out.subarray(0, 5);
  },
  decode: function(d) {
    var family = d[0];
    var cls = d[3] & 0x07;
    var num = d[4];
    var code = cls * 100 + num;
    var reason = d.length > 5 ? _td.decode(d.slice(5)) : '';
    return { family: family, code: code, reason: reason };
  }
};

// RFC 8489 — PASSWORD-ALGORITHM (variable)
attrs[ATTR.PASSWORD_ALGORITHM] = {
  encode: function(v) {
    // v = { algorithm: 0x0001(MD5) or 0x0002(SHA256), params: Uint8Array }
    var params = v.params || new Uint8Array(0);
    var o = new Uint8Array(4 + params.length);
    w_u16(o, 0, v.algorithm);
    w_u16(o, 2, params.length);
    if (params.length) w_bytes(o, 4, params);
    return o;
  },
  decode: function(d) {
    var alg = r_u16(d, 0)[0];
    var len = r_u16(d, 2)[0];
    var params = len > 0 ? d.slice(4, 4 + len) : new Uint8Array(0);
    return { algorithm: alg, params: params };
  }
};

// PASSWORD-ALGORITHMS (list of PASSWORD-ALGORITHM)
attrs[ATTR.PASSWORD_ALGORITHMS] = {
  encode: function(v) {
    var parts = [];
    for (var i = 0; i < v.length; i++) parts.push(attrs[ATTR.PASSWORD_ALGORITHM].encode(v[i]));
    var total = 0; for (var j = 0; j < parts.length; j++) total += parts[j].length;
    var o = new Uint8Array(total);
    var off = 0;
    for (var k = 0; k < parts.length; k++) { o.set(parts[k], off); off += parts[k].length; }
    return o;
  },
  decode: function(d) {
    var out = [];
    var off = 0;
    while (off + 4 <= d.length) {
      var alg = r_u16(d, off)[0];
      var len = r_u16(d, off + 2)[0];
      var params = len > 0 ? d.slice(off + 4, off + 4 + len) : new Uint8Array(0);
      out.push({ algorithm: alg, params: params });
      off += 4 + len + ((4 - (len % 4)) % 4);
    }
    return out;
  }
};


/* ==================== Integrity / Fingerprint ============================== */

// RFC 8265 OpaqueString / SASLprep — basic normalization
// Full SASLprep requires ICU/Unicode tables. This covers the common cases:
// NFKC normalization, trim, reject control characters.
function saslprep(str) {
  if (typeof str !== 'string') return str;
  // NFKC normalization (Node.js supports this natively)
  var normalized = str.normalize('NFKC');
  // Reject ASCII control characters (0x00-0x1F, 0x7F) except space
  for (var i = 0; i < normalized.length; i++) {
    var c = normalized.charCodeAt(i);
    if ((c < 0x20 && c !== 0) || c === 0x7F) return normalized; // pass through, let server reject
  }
  return normalized;
}

function compute_long_term_key(username, realm, password) {
  return crypto.createHash('md5').update(
    saslprep(username) + ':' + saslprep(realm) + ':' + saslprep(password)
  ).digest();
}

// RFC 8489 — long-term key with SHA256
function compute_long_term_key_sha256(username, realm, password) {
  return crypto.createHash('sha256').update(
    saslprep(username) + ':' + saslprep(realm) + ':' + saslprep(password)
  ).digest();
}

function compute_short_term_key(password) {
  return Buffer.from(saslprep(password), 'utf8');
}

// RFC 8489 §14.4 — USERHASH = SHA-256(username ":" realm)
function compute_userhash(username, realm) {
  return new Uint8Array(crypto.createHash('sha256').update(
    saslprep(username) + ':' + saslprep(realm)
  ).digest());
}

// HMAC-SHA1 integrity (RFC 5389)
function compute_integrity(msg_buf, key) {
  var b2 = msg_buf[2], b3 = msg_buf[3];
  var new_len = (msg_buf.length - HEADER_SIZE) + 24;
  msg_buf[2] = (new_len >>> 8) & 0xFF;
  msg_buf[3] = new_len & 0xFF;
  var hmac = new Uint8Array(crypto.createHmac('sha1', key).update(msg_buf).digest());
  msg_buf[2] = b2; msg_buf[3] = b3;
  return hmac;
}

// HMAC-SHA256 integrity (RFC 8489)
function compute_integrity_sha256(msg_buf, key, truncate_len) {
  var b2 = msg_buf[2], b3 = msg_buf[3];
  var hmac_len = truncate_len || 32;
  var new_len = (msg_buf.length - HEADER_SIZE) + 4 + hmac_len;
  msg_buf[2] = (new_len >>> 8) & 0xFF;
  msg_buf[3] = new_len & 0xFF;
  var full_hmac = new Uint8Array(crypto.createHmac('sha256', key).update(msg_buf).digest());
  msg_buf[2] = b2; msg_buf[3] = b3;
  return hmac_len < 32 ? full_hmac.slice(0, hmac_len) : full_hmac;
}

// Generic HMAC integrity for any algorithm (coturn supports SHA384/SHA512)
function compute_integrity_hmac(algo, digest_len, msg_buf, key, truncate_len) {
  var b2 = msg_buf[2], b3 = msg_buf[3];
  var hmac_len = truncate_len || digest_len;
  var new_len = (msg_buf.length - HEADER_SIZE) + 4 + hmac_len;
  msg_buf[2] = (new_len >>> 8) & 0xFF;
  msg_buf[3] = new_len & 0xFF;
  var full_hmac = new Uint8Array(crypto.createHmac(algo, key).update(msg_buf).digest());
  msg_buf[2] = b2; msg_buf[3] = b3;
  return hmac_len < digest_len ? full_hmac.slice(0, hmac_len) : full_hmac;
}

function compute_integrity_sha384(msg_buf, key) {
  return compute_integrity_hmac('sha384', 48, msg_buf, key, 48);
}

function compute_integrity_sha512(msg_buf, key) {
  return compute_integrity_hmac('sha512', 64, msg_buf, key, 64);
}

function validate_integrity_sha256(raw_buf, integrity_offset, key) {
  var attr_len_off = integrity_offset + 2;
  var hmac_len = (raw_buf[attr_len_off] << 8) | raw_buf[attr_len_off + 1];
  var before = raw_buf.slice(0, integrity_offset);
  var expected = compute_integrity_sha256(before, key, hmac_len);
  var actual = raw_buf.slice(integrity_offset + 4, integrity_offset + 4 + hmac_len);
  if (expected.length !== actual.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual));
}

// Generic validation: detects SHA variant by attribute value length
// 20=SHA1, 32=SHA256, 48=SHA384, 64=SHA512
function validate_integrity_by_length(raw_buf, integrity_offset, key) {
  var attr_len_off = integrity_offset + 2;
  var hmac_len = (raw_buf[attr_len_off] << 8) | raw_buf[attr_len_off + 1];
  var before = raw_buf.slice(0, integrity_offset);
  var expected;
  if (hmac_len === 20) expected = compute_integrity(before, key);
  else if (hmac_len <= 32) expected = compute_integrity_sha256(before, key, hmac_len);
  else if (hmac_len === 48) expected = compute_integrity_sha384(before, key);
  else if (hmac_len === 64) expected = compute_integrity_sha512(before, key);
  else return false;
  var actual = raw_buf.slice(integrity_offset + 4, integrity_offset + 4 + hmac_len);
  if (expected.length !== actual.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual));
}

// Timing-safe comparison to prevent timing attacks
function validate_integrity(raw_buf, integrity_offset, key) {
  var before = raw_buf.slice(0, integrity_offset);
  var expected = compute_integrity(before, key);
  var actual = raw_buf.slice(integrity_offset + 4, integrity_offset + 4 + 20);
  if (expected.length !== actual.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual));
}

var crc32_table = new Uint32Array(256);
(function() {
  for (var i = 0; i < 256; i++) {
    var c = i;
    for (var j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    crc32_table[i] = c;
  }
})();

function crc32(buf) {
  var c = 0xFFFFFFFF;
  for (var i = 0; i < buf.length; i++) c = crc32_table[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

var FINGERPRINT_XOR = 0x5354554E;

// Zero-copy: modify length in-place, compute CRC, restore
function compute_fingerprint(msg_buf) {
  var b2 = msg_buf[2], b3 = msg_buf[3];
  var new_len = (msg_buf.length - HEADER_SIZE) + 8;
  msg_buf[2] = (new_len >>> 8) & 0xFF;
  msg_buf[3] = new_len & 0xFF;
  var fp = (crc32(msg_buf) ^ FINGERPRINT_XOR) >>> 0;
  msg_buf[2] = b2; msg_buf[3] = b3;
  return fp;
}

// Legacy add_integrity / add_fingerprint — uses .set() for fast copy
function add_integrity(msg_buf, key) {
  var hmac = compute_integrity(msg_buf, key);
  var out = new Uint8Array(msg_buf.length + 24);
  out.set(msg_buf, 0);
  var off = msg_buf.length;
  off = w_u16(out, off, ATTR.MESSAGE_INTEGRITY);
  off = w_u16(out, off, 20);
  w_bytes(out, off, hmac);
  var new_len = out.length - HEADER_SIZE;
  out[2] = (new_len >>> 8) & 0xFF; out[3] = new_len & 0xFF;
  return out;
}

function add_fingerprint(msg_buf) {
  var fp = compute_fingerprint(msg_buf);
  var out = new Uint8Array(msg_buf.length + 8);
  out.set(msg_buf, 0);
  var off = msg_buf.length;
  off = w_u16(out, off, ATTR.FINGERPRINT);
  off = w_u16(out, off, 4);
  w_u32(out, off, fp);
  var new_len = out.length - HEADER_SIZE;
  out[2] = (new_len >>> 8) & 0xFF; out[3] = new_len & 0xFF;
  return out;
}


/* ========================= RFC 7983 multiplexing ========================= */

// Full demux for WebRTC: STUN, DTLS, RTP, RTCP, TURN ChannelData on same port.
// Based on first-byte ranges defined in RFC 7983 §7.
function is_dtls(buf)  { return buf.length >= 1 && buf[0] >= 20 && buf[0] <= 63; }
function is_rtp(buf)   { return buf.length >= 2 && buf[0] >= 128 && buf[0] <= 191; }
function is_rtcp(buf)  { return buf.length >= 2 && buf[0] >= 128 && buf[0] <= 191 && buf[1] >= 192 && buf[1] <= 223; }

function demux(buf) {
  if (buf.length < 1) return 'unknown';
  var b0 = buf[0];
  if (b0 <= 3)                             return 'stun';     // 0-3
  if (b0 >= 20 && b0 <= 63)               return 'dtls';     // 20-63
  if (b0 >= 0x40 && b0 <= 0x4F)           return 'channel';  // 64-79
  if (b0 >= 128 && b0 <= 191) {                               // 128-191
    return (buf.length >= 2 && buf[1] >= 192 && buf[1] <= 223) ? 'rtcp' : 'rtp';
  }
  return 'unknown';
}

function generateTransactionId() {
  return new Uint8Array(crypto.randomBytes(12));
}

// Standalone STUN validation for ICE connectivity checks.
// Verifies FINGERPRINT and MESSAGE-INTEGRITY (short-term) without creating a Session.
// Returns decoded message on success, null on failure.
function validateStunMessage(buf, password) {
  var msg = decode_message(buf);
  if (!msg) return null;

  // Verify FINGERPRINT if present
  if (msg.fingerprint_offset !== null) {
    var fp_val = msg.getAttribute(ATTR.FINGERPRINT);
    var expected_fp = compute_fingerprint(buf.slice(0, msg.fingerprint_offset));
    if (fp_val !== expected_fp) return null;
  }

  // Verify MESSAGE-INTEGRITY with short-term key (ICE password)
  if (msg.integrity_offset !== null && password) {
    var key = compute_short_term_key(password);
    if (!validate_integrity(buf, msg.integrity_offset, key)) return null;
  }

  return msg;
}


/* ========================= ChannelData / detect ========================== */

function encode_channel_data(channel_number, data) {
  var out = new Uint8Array(4 + data.length);
  w_u16(out, 0, channel_number);
  w_u16(out, 2, data.length);
  w_bytes(out, 4, data);
  return out;
}

// Hot path — subarray (view, zero-copy). Data is fire-and-forget in relay.
function decode_channel_data(buf) {
  var channel; [channel] = r_u16(buf, 0);
  var len;     [len] = r_u16(buf, 2);
  return { channel: channel, data: buf.subarray(4, 4 + len) };
}

function is_stun(buf)         { return buf.length >= 4 && (buf[0] & 0xC0) === 0x00; }
// RFC 7983: TURN ChannelData = first byte 64-79 (0x40-0x4F)
function is_channel_data(buf) { return buf.length >= 4 && buf[0] >= 0x40 && buf[0] <= 0x4F; }

function tcp_frame(data) {
  var out = new Uint8Array(2 + data.length);
  w_u16(out, 0, data.length);
  w_bytes(out, 2, data);
  return out;
}


/* ========================= Message encode ================================ */

// Single-pass encode with optional integrity + fingerprint — one allocation
function encode_message(options) {
  var method = options.method || METHOD.BINDING;
  var cls = options.cls || CLASS.REQUEST;
  var tid = options.transactionId || new Uint8Array(crypto.randomBytes(12));
  var key = options.key || null;
  var do_fingerprint = options.fingerprint !== false;
  var integrity_algo = options.integrity || 'sha1'; // 'sha1' | 'sha256'
  var attribute_list = options.attributes || [];

  var encoded_attrs = [];
  var attrs_len = 0;

  for (var i = 0; i < attribute_list.length; i++) {
    var a = attribute_list[i];
    var type = a.type;
    var vb;
    if (a.raw) { vb = a.raw; }
    else if (attrs[type] && attrs[type].encode) {
      vb = (type === ATTR.XOR_MAPPED_ADDRESS || type === ATTR.XOR_PEER_ADDRESS || type === ATTR.XOR_RELAYED_ADDRESS)
        ? attrs[type].encode(a.value, tid) : attrs[type].encode(a.value);
    } else { vb = a.value instanceof Uint8Array ? a.value : new Uint8Array(0); }

    var padded = vb.length + ((4 - (vb.length % 4)) % 4);
    attrs_len += 4 + padded;
    encoded_attrs.push({ type: type, value: vb, padded: padded });
  }

  // Integrity size: SHA1=4+20=24, SHA256=4+32=36, SHA384=4+48=52, SHA512=4+64=68
  var hmac_sizes = { sha1: 20, sha256: 32, sha384: 48, sha512: 64 };
  var hmac_len = hmac_sizes[integrity_algo] || 20;
  var integrity_size = key ? (4 + hmac_len) : 0;
  var total = HEADER_SIZE + attrs_len + integrity_size + (do_fingerprint ? 8 : 0);
  var buf = new Uint8Array(total);
  var off = 0;

  off = w_u16(buf, off, encode_type(method, cls));
  off = w_u16(buf, off, attrs_len);
  off = w_u32(buf, off, MAGIC_COOKIE);
  off = w_bytes(buf, off, tid);

  for (var j = 0; j < encoded_attrs.length; j++) {
    var ea = encoded_attrs[j];
    off = w_u16(buf, off, ea.type);
    off = w_u16(buf, off, ea.value.length);
    off = w_bytes(buf, off, ea.value);
    off += ea.padded - ea.value.length;
  }

  if (key) {
    var i_attr = (integrity_algo === 'sha1')
      ? ATTR.MESSAGE_INTEGRITY : ATTR.MESSAGE_INTEGRITY_SHA256;
    var i_hmac;
    if (integrity_algo === 'sha384') i_hmac = compute_integrity_sha384(buf.subarray(0, off), key);
    else if (integrity_algo === 'sha512') i_hmac = compute_integrity_sha512(buf.subarray(0, off), key);
    else if (integrity_algo === 'sha256') i_hmac = compute_integrity_sha256(buf.subarray(0, off), key, 32);
    else i_hmac = compute_integrity(buf.subarray(0, off), key);

    off = w_u16(buf, off, i_attr);
    off = w_u16(buf, off, i_hmac.length);
    off = w_bytes(buf, off, i_hmac);
    buf[2] = ((off - HEADER_SIZE) >>> 8) & 0xFF;
    buf[3] = (off - HEADER_SIZE) & 0xFF;
  }

  if (do_fingerprint) {
    var fp = compute_fingerprint(buf.subarray(0, off));
    off = w_u16(buf, off, ATTR.FINGERPRINT);
    off = w_u16(buf, off, 4);
    off = w_u32(buf, off, fp);
    buf[2] = ((off - HEADER_SIZE) >>> 8) & 0xFF;
    buf[3] = (off - HEADER_SIZE) & 0xFF;
  }

  return { buf: buf, transactionId: tid };
}


/* ========================= Message decode ================================ */

// Shared getAttribute — avoids per-message closure allocation
function _getAttribute(type) {
  return this.attr[type] !== undefined ? this.attr[type] : null;
}

function decode_message(buf) {
  if (buf.length < HEADER_SIZE) return null;

  var off = 0;
  var raw_type; [raw_type, off] = r_u16(buf, off);
  if ((raw_type & 0xC000) !== 0) return null;

  var dt = decode_type(raw_type);
  var msg_len; [msg_len, off] = r_u16(buf, off);
  var cookie;  [cookie, off] = r_u32(buf, off);
  if (cookie !== MAGIC_COOKIE) return null;

  var tid; [tid, off] = r_bytes(buf, off, 12);
  if (HEADER_SIZE + msg_len > buf.length) return null;

  // RFC 5389 §6: message length MUST be a multiple of 4
  if (msg_len % 4 !== 0) return null;

  var attributes = [];
  var attribute_map = {};
  var integrity_offset = null;
  var integrity_sha256_offset = null;
  var fingerprint_offset = null;
  var end = HEADER_SIZE + msg_len;

  while (off + 4 <= end) {
    var at; [at, off] = r_u16(buf, off);
    var al; [al, off] = r_u16(buf, off);
    if (off + al > end) break;

    var ar; [ar, ] = r_bytes(buf, off, al);

    if (at === ATTR.MESSAGE_INTEGRITY) integrity_offset = off - 4;
    if (at === ATTR.MESSAGE_INTEGRITY_SHA256) integrity_sha256_offset = off - 4;
    if (at === ATTR.FINGERPRINT) fingerprint_offset = off - 4;

    var dv = ar;
    if (attrs[at] && attrs[at].decode) {
      dv = (at === ATTR.XOR_MAPPED_ADDRESS || at === ATTR.XOR_PEER_ADDRESS || at === ATTR.XOR_RELAYED_ADDRESS)
        ? attrs[at].decode(ar, tid) : attrs[at].decode(ar);
    }

    attributes.push({ type: at, value: dv, raw: ar });
    attribute_map[at] = dv;

    off += al + ((4 - (al % 4)) % 4);
  }

  return {
    method: dt.method, cls: dt.cls,
    methodName: METHOD_NAME[dt.method] || null,
    className: CLASS_NAME[dt.cls] || null,
    transactionId: tid, length: msg_len,
    attributes: attributes, attr: attribute_map,
    raw: buf,
    integrity_offset: integrity_offset,
    integrity_sha256_offset: integrity_sha256_offset,
    fingerprint_offset: fingerprint_offset,
    getAttribute: _getAttribute,
  };
}


/* ============================== Exports ================================== */

// RFC 7064/7065 — STUN/TURN URI parsing
// IPv4: stun:host:port, turn:host:port?transport=udp
// IPv6: stun:[::1]:port, turn:[2001:db8::1]:port?transport=tcp
function parseUri(uri) {
  // Try IPv6 bracket notation first: scheme:[ipv6]:port?params
  var m = uri.match(/^(stuns?|turns?):\[([^\]]+)\](?::(\d+))?(?:\?(.*))?$/);
  // Fall back to IPv4/hostname: scheme:host:port?params
  if (!m) m = uri.match(/^(stuns?|turns?):([^?:]+)(?::(\d+))?(?:\?(.*))?$/);
  if (!m) return null;

  var scheme = m[1];
  var host = m[2];
  var port = m[3] ? parseInt(m[3], 10) : null;
  var params = {};

  if (m[4]) {
    m[4].split('&').forEach(function(p) {
      var kv = p.split('=');
      params[kv[0]] = kv[1] || '';
    });
  }

  var secure = scheme === 'stuns' || scheme === 'turns';
  var isTurn = scheme === 'turn' || scheme === 'turns';
  var transport = params.transport || (secure ? 'tls' : 'udp');

  if (!port) {
    port = secure ? 5349 : 3478;
  }

  return {
    scheme: scheme,
    host: host,
    port: port,
    transport: transport,
    secure: secure,
    isTurn: isTurn,
    params: params,
  };
}


export {
  MAGIC_COOKIE, MAGIC_COOKIE_BUF, HEADER_SIZE,
  METHOD, CLASS, ATTR, ERROR_CODE, ERROR_REASON, TRANSPORT, FAMILY,
  METHOD_NAME, CLASS_NAME, FINGERPRINT_XOR,
  w_u8, w_u16, w_u32, w_bytes, r_u8, r_u16, r_u32, r_bytes,
  parse_ipv4, format_ipv4, parse_ipv6, format_ipv6, detect_family,
  encode_type, decode_type,
  attrs,
  encode_message, decode_message,
  compute_long_term_key, compute_long_term_key_sha256, compute_short_term_key, compute_userhash, saslprep,
  compute_integrity, validate_integrity,
  compute_integrity_sha256, validate_integrity_sha256,
  compute_integrity_sha384, compute_integrity_sha512,
  compute_integrity_hmac, validate_integrity_by_length,
  add_integrity, add_fingerprint, compute_fingerprint,
  encode_channel_data, decode_channel_data, is_stun, is_channel_data,
  tcp_frame, parseUri,
  // RFC 7983 multiplexing (WebRTC stack)
  is_dtls, is_rtp, is_rtcp, demux,
  generateTransactionId, validateStunMessage,
};
