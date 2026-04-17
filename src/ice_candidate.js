// src/ice_candidate.js
// Pure ICE candidate primitives — no state, no sockets, no agent.
// Safe to import from the SDP layer for parseCandidate / formatCandidate.
//
// Spec references:
//   RFC 8445 §5.1.2   — priority formula
//   RFC 8445 §5.1.1.3 — foundation rules
//   RFC 8445 §6.1.2.3 — pair priority
//   RFC 8839 §B.1     — SDP candidate-attribute ABNF grammar
//   RFC 8839 §5.3     — end-of-candidates attribute
//   RFC 4566          — SDP connection-address (IP4 / IP6 / FQDN / extn-addr)
//   RFC 6544 §4.5     — tcptype values (active / passive / so)
//
// Official ABNF (RFC 8839 §B.1):
//
//   candidate-attribute = "candidate" ":" foundation SP component-id SP
//                         transport SP priority SP connection-address SP
//                         port SP cand-type
//                         [SP rel-addr] [SP rel-port]
//                         *(SP cand-extension)
//
//   foundation          = 1*32 ice-char
//   component-id        = 1*3 DIGIT
//   transport           = "UDP" / transport-extension
//   transport-extension = token
//   priority            = 1*10 DIGIT
//   cand-type           = "typ" SP candidate-types
//   candidate-types     = "host" / "srflx" / "prflx" / "relay" / token
//   rel-addr            = "raddr" SP connection-address
//   rel-port            = "rport" SP port
//   cand-extension      = extension-att-name SP extension-att-value
//   extension-att-name  = token
//   extension-att-value = *VCHAR
//   ice-char            = ALPHA / DIGIT / "+" / "/"

import crypto from 'node:crypto';


/* ========================= Type preferences ========================= */
// RFC 8445 §5.1.2.2 — recommended preferences

const TYPE_PREFERENCE = {
  host:   126,
  prflx:  110,
  srflx:  100,
  relay:    0,
};

// Well-known candidate types (RFC 8445 §5.1.1.1).
// Non-standard tokens are also legal per RFC 8839 ABNF.
const STANDARD_TYPES = ['host', 'srflx', 'prflx', 'relay'];

// Well-known TCP candidate types (RFC 6544 §4.5).
const STANDARD_TCP_TYPES = ['active', 'passive', 'so'];

// SDP trickle ICE end-of-candidates marker (RFC 8839 §5.3).
const END_OF_CANDIDATES_LINE = 'a=end-of-candidates';


/* ========================= Priority ========================= */

/**
 * Compute a candidate priority.
 *   priority = 2^24 * typePref + 2^8 * localPref + (256 − componentId)
 * Using multiplication (not bit-shift) because typePref*2^24 overflows int32.
 * RFC 8445 §5.1.2.1.
 *
 * @param type         'host' | 'srflx' | 'prflx' | 'relay' | (any string; unknown → 0)
 * @param localPref    0..65535; default 65535
 * @param componentId  1..256;  default 1
 * @returns integer in the range [0, 2^31 - 1]
 */
function computeCandidatePriority(type, localPreference, componentId) {
  const typePref  = TYPE_PREFERENCE[type] || 0;
  const localPref = (localPreference == null) ? 65535 : localPreference;
  const compId    = componentId || 1;
  return (typePref * 0x01000000) + (localPref * 0x100) + (256 - compId);
}

/**
 * Compute a candidate-pair priority.
 *   priority = 2^32 * min(G,D) + 2 * max(G,D) + (G>D ? 1 : 0)
 * where G = controlling priority, D = controlled priority.
 * RFC 8445 §6.1.2.3.
 *
 * NOTE: For realistic candidate priorities (~2^31), this exceeds
 * Number.MAX_SAFE_INTEGER (2^53). The min*2^32 term dominates and
 * sort ordering is preserved; exact tie-breaking between pairs with
 * identical min priority may lose a few low bits. All pure-JS ICE
 * implementations share this limitation.
 */
function computePairPriority(controlling, localPriority, remotePriority) {
  const G = controlling ? localPriority : remotePriority;
  const D = controlling ? remotePriority : localPriority;
  const min = Math.min(G, D);
  const max = Math.max(G, D);
  return (min * 0x100000000) + (max * 2) + (G > D ? 1 : 0);
}


/* ========================= Foundation ========================= */

/**
 * Compute an ICE foundation.
 *   Same foundation ⇔ same type + same base + same STUN/TURN server + same protocol.
 * RFC 8445 §5.1.1.3.
 *
 * Output: 8-char lowercase hex (from MD5 prefix). All chars are valid ice-chars.
 * Fits `1*32 ice-char` rule.
 *
 * @param type        'host' | 'srflx' | 'prflx' | 'relay'
 * @param baseIp      host IP (the base)
 * @param protocol    'udp' | 'tcp'
 * @param stunServer  identifying string for the STUN/TURN server used to obtain
 *                    this candidate (empty string for 'host' and 'prflx').
 */
function computeFoundation(type, baseIp, protocol, stunServer) {
  const input = type + '|' + baseIp + '|' + (protocol || 'udp') + '|' + (stunServer || '');
  return crypto.createHash('md5').update(input).digest('hex').slice(0, 8);
}


/* ========================= Formatting / parsing ========================= */

// VCHAR per RFC 5234: %x21-7E (printable ASCII, excluding space).
// Used to reject extension values containing control chars / spaces.
const VCHAR_RE = /^[\x21-\x7E]+$/;

// token per RFC 3261
const TOKEN_RE = /^[A-Za-z0-9\-.!%*_+`'~]+$/;

// ice-char per RFC 8839: ALPHA / DIGIT / "+" / "/"
const ICE_CHAR_RE = /^[A-Za-z0-9+/]+$/;


/**
 * Serialize a candidate object into an SDP attribute value (without `a=candidate:`).
 * Returns an empty string if required fields are missing or invalid.
 * RFC 8839 §B.1 compliant.
 *
 * Required: foundation, component, protocol, priority, ip, port, type.
 * Optional: relatedAddress, relatedPort, tcpType, extensions.
 */
function formatCandidate(c) {
  if (!c || typeof c !== 'object') return '';

  // Required fields — reject silently rather than producing broken SDP.
  if (!c.foundation || typeof c.foundation !== 'string') return '';
  if (!Number.isFinite(c.component) || c.component < 1 || c.component > 256) return '';
  if (!c.protocol || typeof c.protocol !== 'string') return '';
  if (!Number.isFinite(c.priority) || c.priority < 0) return '';
  if (!c.ip || typeof c.ip !== 'string') return '';
  if (!Number.isFinite(c.port) || c.port < 0 || c.port > 65535) return '';
  if (!c.type || typeof c.type !== 'string') return '';

  // Canonical form: lowercase protocol + type (matches Chrome/Firefox output).
  const protocol = c.protocol.toLowerCase();
  const type     = c.type.toLowerCase();

  let s = c.foundation + ' ' + c.component + ' ' + protocol + ' ' +
          c.priority + ' ' + c.ip + ' ' + c.port + ' typ ' + type;

  if (c.relatedAddress) {
    s += ' raddr ' + c.relatedAddress;
  }
  if (c.relatedPort != null && Number.isFinite(c.relatedPort)) {
    s += ' rport ' + c.relatedPort;
  }
  if (c.tcpType && typeof c.tcpType === 'string') {
    // RFC 6544 §4.5: tcptype is an SDP extension, goes as a regular ext.
    s += ' tcptype ' + c.tcpType.toLowerCase();
  }

  // Preserve any additional extension attributes (forward compat).
  if (c.extensions && typeof c.extensions === 'object') {
    const keys = Object.keys(c.extensions);
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      const v = c.extensions[k];
      if (v == null) continue;  // skip undefined values
      // Per ABNF: extension-att-value = *VCHAR (no spaces).
      // If value contains whitespace we'd produce invalid SDP. Coerce + strip.
      const vStr = String(v).replace(/\s+/g, '');
      if (vStr === '') continue;
      s += ' ' + k + ' ' + vStr;
    }
  }
  return s;
}


/**
 * Build a full SDP candidate line (with `candidate:` prefix, no `a=`).
 * Use for including in SDP; SDP serializers typically prepend `a=` themselves.
 */
function buildCandidateAttr(c) {
  const v = formatCandidate(c);
  return v ? 'candidate:' + v : '';
}


/**
 * Parse an SDP candidate line into a candidate object.
 * Accepts any of: `a=candidate:...`, `candidate:...`, or the raw value (no prefix).
 * Returns null on parse failure.
 *
 * Lenient parser — only rejects structurally malformed input. Does NOT enforce
 * semantic constraints (component 1-256, priority range, etc.). This is
 * deliberate: peer implementations occasionally emit slightly off-spec
 * candidates; we prefer interop over strict validation.
 *
 * For strict validation, call validateCandidate() on the result.
 */
function parseCandidate(str) {
  if (!str || typeof str !== 'string') return null;

  // Normalize: trim, strip optional `a=` prefix, strip `candidate:` prefix, trim again.
  let s = str.trim();
  if (s.startsWith('a=') || s.startsWith('A=')) s = s.slice(2);
  if (s.startsWith('candidate:')) s = s.slice(10);
  s = s.trim();

  // Split on any run of whitespace.
  const p = s.split(/\s+/);

  // Minimum viable: foundation comp proto prio ip port typ X = 8 tokens.
  if (p.length < 8) return null;

  const component = parseInt(p[1], 10);
  const priority  = parseInt(p[3], 10);
  const port      = parseInt(p[5], 10);

  if (!Number.isFinite(component) || !Number.isFinite(priority) || !Number.isFinite(port)) {
    return null;
  }
  if (p[6] !== 'typ') return null;

  // Clean IPv6 zone id if present (rare but legal in non-SDP contexts).
  // In SDP we strip it — agents shouldn't expose local interface names.
  const ip = stripZoneId(p[4]);

  const cand = {
    foundation:     p[0],
    component:      component,
    protocol:       p[2].toLowerCase(),   // canonical lower-case
    priority:       priority,
    ip:             ip,
    port:           port,
    type:           (p[7] || '').toLowerCase(),  // canonical lower-case
    relatedAddress: null,
    relatedPort:    null,
    tcpType:        null,
    extensions:     null,
  };

  if (!cand.type) return null;

  // Walk remaining tokens as key-value pairs.
  for (let i = 8; i + 1 < p.length; i += 2) {
    const k = p[i];
    const v = p[i + 1];

    switch (k) {
      case 'raddr':
        cand.relatedAddress = stripZoneId(v);
        break;
      case 'rport':
        {
          const rp = parseInt(v, 10);
          if (Number.isFinite(rp)) cand.relatedPort = rp;
        }
        break;
      case 'tcptype':
        cand.tcpType = v.toLowerCase();
        break;
      default:
        // Unknown extension — preserve verbatim (forward-compat).
        if (!cand.extensions) cand.extensions = {};
        cand.extensions[k] = v;
    }
  }

  return cand;
}


/**
 * Is this line the end-of-candidates marker?
 * RFC 8839 §5.3: `a=end-of-candidates` (session or media level, no value).
 */
function isEndOfCandidatesLine(line) {
  if (!line || typeof line !== 'string') return false;
  const s = line.trim();
  return s === 'a=end-of-candidates' || s === 'end-of-candidates';
}


/* ========================= Validation ========================= */

/**
 * Strict validation against RFC 8839 ABNF + RFC 8445 semantic constraints.
 * Returns null if valid, or an array of error strings describing violations.
 * Never throws.
 *
 * Use after parseCandidate() when you want RFC compliance (e.g. logging
 * off-spec peers) — but note that many real-world peers produce slightly
 * off-spec output that still interops fine.
 */
function validateCandidate(c) {
  if (!c || typeof c !== 'object') return ['not an object'];
  const errs = [];

  // foundation — 1*32 ice-char
  if (typeof c.foundation !== 'string' || c.foundation.length < 1 || c.foundation.length > 32) {
    errs.push('foundation length must be 1..32');
  } else if (!ICE_CHAR_RE.test(c.foundation)) {
    errs.push('foundation contains non-ice-char');
  }

  // component-id — 1..256 per RFC 8445 §15
  if (!Number.isInteger(c.component) || c.component < 1 || c.component > 256) {
    errs.push('component must be integer 1..256');
  }

  // transport — "UDP" (or token per ABNF, but in practice udp/tcp)
  if (typeof c.protocol !== 'string' || !TOKEN_RE.test(c.protocol)) {
    errs.push('protocol must be a token');
  }

  // priority — 1..(2^31 - 1) per RFC 8445 §5.1.2.1
  if (!Number.isInteger(c.priority) || c.priority < 1 || c.priority > 2147483647) {
    errs.push('priority must be integer 1..(2^31-1)');
  }

  // connection-address — we accept IPv4/IPv6/FQDN (per RFC 4566). No format check.
  if (typeof c.ip !== 'string' || c.ip.length === 0) {
    errs.push('ip/connection-address missing');
  }

  // port — 0..65535
  if (!Number.isInteger(c.port) || c.port < 0 || c.port > 65535) {
    errs.push('port must be integer 0..65535');
  }

  // type — token (includes well-known + extensions)
  if (typeof c.type !== 'string' || !TOKEN_RE.test(c.type)) {
    errs.push('type must be a token');
  }

  // raddr / rport — if one is present, the other should be too
  if (c.relatedAddress != null && c.relatedPort == null) {
    errs.push('relatedAddress set but relatedPort missing');
  }
  if (c.relatedPort != null) {
    if (!Number.isInteger(c.relatedPort) || c.relatedPort < 0 || c.relatedPort > 65535) {
      errs.push('relatedPort must be integer 0..65535');
    }
  }

  // tcpType — active / passive / so (RFC 6544 §4.5), only for tcp
  if (c.tcpType != null) {
    if (typeof c.tcpType !== 'string' || STANDARD_TCP_TYPES.indexOf(c.tcpType.toLowerCase()) < 0) {
      errs.push('tcpType must be one of: ' + STANDARD_TCP_TYPES.join(', '));
    }
    if (c.protocol && c.protocol.toLowerCase() !== 'tcp') {
      errs.push('tcpType only valid with tcp protocol');
    }
  }

  // extensions — each value must be *VCHAR, each key a token
  if (c.extensions && typeof c.extensions === 'object') {
    const keys = Object.keys(c.extensions);
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      const v = c.extensions[k];
      if (!TOKEN_RE.test(k)) errs.push('extension name "' + k + '" is not a token');
      if (v != null && !VCHAR_RE.test(String(v))) {
        errs.push('extension "' + k + '" value has non-VCHAR');
      }
    }
  }

  return errs.length === 0 ? null : errs;
}


/* ========================= Address helpers ========================= */

/**
 * IPv4 / IPv6 classifier. Accepts bare addresses; zone IDs are ignored.
 * Returns 'IPv4' for IPv4, FQDN, mDNS, or anything without colons (default).
 * Returns 'IPv6' for addresses containing ':'.
 */
function addressFamilyOf(ip) {
  if (!ip || typeof ip !== 'string') return 'IPv4';
  return ip.indexOf(':') >= 0 ? 'IPv6' : 'IPv4';
}

/**
 * Strip an IPv6 zone identifier (e.g. "fe80::1%eth0" → "fe80::1").
 * Zone IDs are a local concept and should not appear in SDP.
 */
function stripZoneId(ip) {
  if (!ip || typeof ip !== 'string') return ip;
  const idx = ip.indexOf('%');
  return idx >= 0 ? ip.substring(0, idx) : ip;
}

/**
 * Does this hostname look like an mDNS ICE candidate (RFC 8828)?
 * Chrome emits these to protect host IPs from being leaked via ICE.
 */
function isMdnsHost(ip) {
  return typeof ip === 'string' && /\.local$/i.test(ip);
}


/* ========================= Keys ========================= */
// Helpers for set-lookup / dedup inside the agent.

function candidateKey(c) {
  return c.component + ':' + c.protocol + ':' + c.ip + ':' + c.port;
}

function pairKey(local, remote) {
  return candidateKey(local) + '→' + candidateKey(remote);
}


/* ========================= Exports ========================= */

export {
  // Constants
  TYPE_PREFERENCE,
  STANDARD_TYPES,
  STANDARD_TCP_TYPES,
  END_OF_CANDIDATES_LINE,

  // Computation
  computeCandidatePriority,
  computePairPriority,
  computeFoundation,

  // Formatting / parsing
  formatCandidate,
  buildCandidateAttr,
  parseCandidate,
  isEndOfCandidatesLine,
  validateCandidate,

  // Address helpers
  addressFamilyOf,
  stripZoneId,
  isMdnsHost,

  // Keys
  candidateKey,
  pairKey,
};
