/**
 * Peer address policy — which addresses a TURN relay may send to.
 *
 * A TURN relay sends whatever a client gives it to whatever address the client
 * names. Left open, that turns the server into a proxy into its own network:
 * the router's admin page, other machines on the LAN, cloud metadata at
 * 169.254.169.254, services bound to localhost. That is CVE-2020-26262 in
 * coturn (loopback and 0.0.0.0) and CVE-2026-27624 (the same addresses
 * written as IPv4-mapped IPv6, which slipped past the check), and the class of
 * bug Enable Security found in most public TURN deployments.
 *
 * So the check works on the address bytes, never on its spelling: an IPv6
 * address that carries an IPv4 one (::ffff:a.b.c.d, ::a.b.c.d, 64:ff9b::/96
 * NAT64, 2002::/16 6to4) is judged by the IPv4 address inside it.
 *
 * Order of decision:
 *   1. not an IP address, or an unspecified / reserved address  → blocked, always
 *   2. in options.allowedPeers                                  → allowed
 *   3. in options.deniedPeers                                   → blocked
 *   4. loopback        → blocked unless allowLoopback
 *      multicast/bcast → blocked unless allowMulticast
 *      private / link-local / CGNAT / ULA / documentation …  → blocked unless allowPrivatePeers
 *   5. anything else (public unicast)                        → allowed
 *
 * allowedPeers / deniedPeers are lists of CIDR strings ('10.0.0.0/8',
 * '2001:db8::/32') or single addresses — the counterparts of coturn's
 * allowed-peer-ip / denied-peer-ip.
 */

import net from 'node:net';


/* ------------------------------ parsing ------------------------------ */

function v4_bytes(str) {
  var p = str.split('.');
  return [p[0] | 0, p[1] | 0, p[2] | 0, p[3] | 0];
}

// Full 16 bytes for any valid IPv6 spelling, including a dotted IPv4 tail
// (::ffff:127.0.0.1) and a zone id (fe80::1%eth0).
function v6_bytes(str) {
  var pct = str.indexOf('%');
  if (pct >= 0) str = str.slice(0, pct);

  var tail = null;
  var lastColon = str.lastIndexOf(':');
  if (str.indexOf('.', lastColon) > lastColon) {
    tail = v4_bytes(str.slice(lastColon + 1));
    str = str.slice(0, lastColon) + ':0:0';
  }

  var halves = str.split('::');
  var left = halves[0] ? halves[0].split(':') : [];
  var right = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  var groups = left.slice();
  for (var i = 0; i < 8 - left.length - right.length; i++) groups.push('0');
  groups = groups.concat(right);

  var out = new Array(16);
  for (var g = 0; g < 8; g++) {
    var v = parseInt(groups[g] || '0', 16) & 0xFFFF;
    out[g * 2] = v >> 8;
    out[g * 2 + 1] = v & 0xFF;
  }
  if (tail) { out[12] = tail[0]; out[13] = tail[1]; out[14] = tail[2]; out[15] = tail[3]; }
  return out;
}

// → { v: 4, b: [4 bytes] } | { v: 6, b: [16 bytes] } | null
function parse(ip) {
  if (typeof ip !== 'string') return null;
  var bare = ip.indexOf('%') >= 0 ? ip.slice(0, ip.indexOf('%')) : ip;
  if (net.isIPv4(bare)) return { v: 4, b: v4_bytes(bare) };
  if (net.isIPv6(bare)) return { v: 6, b: v6_bytes(ip) };
  return null;
}

// An IPv6 address that carries an IPv4 address → that IPv4 address, else null.
function embedded_v4(b) {
  var zero10 = true;
  for (var i = 0; i < 10; i++) if (b[i] !== 0) { zero10 = false; break; }

  // ::ffff:a.b.c.d (IPv4-mapped) and ::ffff:0:a.b.c.d (IPv4-translated)
  if (zero10 && b[10] === 0xFF && b[11] === 0xFF) return b.slice(12, 16);
  if (zero10 && b[10] === 0 && b[11] === 0) {
    // ::a.b.c.d (IPv4-compatible, deprecated) — but not :: and ::1
    var tailZero = b[12] === 0 && b[13] === 0 && b[14] === 0;
    if (!(tailZero && (b[15] === 0 || b[15] === 1))) return b.slice(12, 16);
  }
  var z8 = true;
  for (var j = 0; j < 8; j++) if (b[j] !== 0) { z8 = false; break; }
  if (z8 && b[8] === 0xFF && b[9] === 0xFF && b[10] === 0 && b[11] === 0) return b.slice(12, 16);

  // 64:ff9b::/96 — NAT64 well-known prefix (RFC 6052)
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xFF && b[3] === 0x9B) {
    var mid = true;
    for (var k = 4; k < 12; k++) if (b[k] !== 0) { mid = false; break; }
    if (mid) return b.slice(12, 16);
  }
  // 64:ff9b:1::/48 — local-use NAT64 (RFC 8215): always local, embedded at the end
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xFF && b[3] === 0x9B && b[4] === 0x00 && b[5] === 0x01) {
    return b.slice(12, 16);
  }
  // 2002::/16 — 6to4: the IPv4 address is bytes 2..5
  if (b[0] === 0x20 && b[1] === 0x02) return b.slice(2, 6);
  return null;
}


/* --------------------------- classification --------------------------- */

function in4(b, a0, a1, a2, a3, bits) {
  var net4 = [a0, a1, a2, a3];
  for (var i = 0; i < 4 && bits > 0; i++, bits -= 8) {
    var m = bits >= 8 ? 0xFF : (0xFF << (8 - bits)) & 0xFF;
    if ((b[i] & m) !== (net4[i] & m)) return false;
  }
  return true;
}

// 'reserved' (always blocked), 'loopback', 'multicast', 'private', or null (public)
function class_v4(b) {
  if (in4(b, 0, 0, 0, 0, 8))         return 'reserved';   // "this network", 0.0.0.0
  if (in4(b, 240, 0, 0, 0, 4))       return 'reserved';   // 240/4 incl. 255.255.255.255
  if (in4(b, 127, 0, 0, 0, 8))       return 'loopback';
  if (in4(b, 224, 0, 0, 0, 4))       return 'multicast';
  if (in4(b, 10, 0, 0, 0, 8))        return 'private';    // RFC 1918
  if (in4(b, 172, 16, 0, 0, 12))     return 'private';    // RFC 1918
  if (in4(b, 192, 168, 0, 0, 16))    return 'private';    // RFC 1918
  if (in4(b, 169, 254, 0, 0, 16))    return 'private';    // link-local, cloud metadata
  if (in4(b, 100, 64, 0, 0, 10))     return 'private';    // CGNAT (RFC 6598)
  if (in4(b, 192, 0, 0, 0, 24))      return 'private';    // IETF protocol assignments
  if (in4(b, 192, 0, 2, 0, 24))      return 'private';    // TEST-NET-1
  if (in4(b, 198, 18, 0, 0, 15))     return 'private';    // benchmarking
  if (in4(b, 198, 51, 100, 0, 24))   return 'private';    // TEST-NET-2
  if (in4(b, 203, 0, 113, 0, 24))    return 'private';    // TEST-NET-3
  return null;
}

function class_v6(b) {
  var allZero = true;
  for (var i = 0; i < 15; i++) if (b[i] !== 0) { allZero = false; break; }
  if (allZero && b[15] === 0) return 'reserved';                  // ::
  if (allZero && b[15] === 1) return 'loopback';                  // ::1

  var v4 = embedded_v4(b);
  if (v4) return class_v4(v4);

  if (b[0] === 0xFF) return 'multicast';                          // ff00::/8
  if (b[0] === 0xFE && (b[1] & 0xC0) === 0x80) return 'private';  // fe80::/10 link-local
  if (b[0] === 0xFE && (b[1] & 0xC0) === 0xC0) return 'private';  // fec0::/10 site-local (deprecated)
  if ((b[0] & 0xFE) === 0xFC) return 'private';                   // fc00::/7 unique local
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0D && b[3] === 0xB8) return 'private'; // 2001:db8::/32 docs
  if (b[0] === 0x01 && b[1] === 0x00 && b[2] === 0 && b[3] === 0 &&
      b[4] === 0 && b[5] === 0 && b[6] === 0 && b[7] === 0) return 'reserved';         // 100::/64 discard
  return null;
}


/* ------------------------------ CIDR lists ----------------------------- */

function parse_cidr(s) {
  if (typeof s !== 'string') throw new TypeError('peer range must be a string: ' + s);
  var slash = s.indexOf('/');
  var addr = slash >= 0 ? s.slice(0, slash) : s;
  var p = parse(addr);
  if (!p) throw new TypeError('not an IP address or CIDR range: ' + s);
  var max = p.v === 4 ? 32 : 128;
  var bits = slash >= 0 ? parseInt(s.slice(slash + 1), 10) : max;
  if (!(bits >= 0 && bits <= max)) throw new TypeError('bad prefix length: ' + s);
  return { v: p.v, b: p.b, bits: bits };
}

function compile_ranges(list) {
  if (!list) return [];
  if (!Array.isArray(list)) list = [list];
  return list.map(parse_cidr);
}

function match_range(p, r) {
  if (p.v !== r.v) return false;
  var bits = r.bits;
  for (var i = 0; bits > 0; i++, bits -= 8) {
    var m = bits >= 8 ? 0xFF : (0xFF << (8 - bits)) & 0xFF;
    if ((p.b[i] & m) !== (r.b[i] & m)) return false;
  }
  return true;
}

// An address matches a range written in either family: 192.168.0.0/16 also
// catches ::ffff:192.168.1.1.
function in_ranges(p, ranges) {
  if (!ranges.length) return false;
  var alt = null;
  if (p.v === 6) { var e = embedded_v4(p.b); if (e) alt = { v: 4, b: e }; }
  for (var i = 0; i < ranges.length; i++) {
    if (match_range(p, ranges[i])) return true;
    if (alt && match_range(alt, ranges[i])) return true;
  }
  return false;
}


/* ------------------------------- policy -------------------------------- */

/**
 * createPeerPolicy({ allowLoopback, allowMulticast, allowPrivatePeers,
 *                    allowedPeers, deniedPeers })
 *   → { isBlocked(ip) → bool, classify(ip) → string|null }
 *
 * Throws TypeError on a malformed range, so a typo in the config fails at
 * startup instead of silently allowing everything.
 */
function createPeerPolicy(options) {
  options = options || {};
  var allowed = compile_ranges(options.allowedPeers);
  var denied = compile_ranges(options.deniedPeers);

  function classify(ip) {
    var p = parse(ip);
    if (!p) return 'invalid';
    return p.v === 4 ? class_v4(p.b) : class_v6(p.b);
  }

  function isBlocked(ip) {
    var p = parse(ip);
    if (!p) return true;
    var cls = p.v === 4 ? class_v4(p.b) : class_v6(p.b);
    if (cls === 'reserved') return true;

    if (in_ranges(p, allowed)) return false;
    if (in_ranges(p, denied)) return true;

    if (cls === 'loopback')  return !options.allowLoopback;
    if (cls === 'multicast') return !options.allowMulticast;
    if (cls === 'private')   return !options.allowPrivatePeers;
    return false;
  }

  return { isBlocked: isBlocked, classify: classify };
}

/**
 * Did the administrator name this peer explicitly? True for an address in
 * allowedPeers, and for a loopback address under allowLoopback. The server's
 * own-address rule (Server isSelfService) yields to these: they are a decision
 * about exactly this address, where the own-address rule is a default.
 */
function isExplicitlyAllowed(ip, options, compiledAllowed) {
  var p = parse(ip);
  if (!p) return false;
  if (compiledAllowed && in_ranges(p, compiledAllowed)) return true;
  var cls = p.v === 4 ? class_v4(p.b) : class_v6(p.b);
  return cls === 'loopback' && !!options.allowLoopback;
}

export { createPeerPolicy, compile_ranges as compilePeerRanges, isExplicitlyAllowed };
