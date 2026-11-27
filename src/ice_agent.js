// src/ice_agent.js
// ICE Agent (RFC 8445) — interactive connectivity establishment.
// Supports: full ICE + ICE-Lite, vanilla + trickle gathering, connectivity
// checks and nomination as Chrome (libwebrtc) runs them — switching to a
// better pair after connecting, liveness from the selected pair's checks —
// ICE restart, TURN permissions for relay, IPv4 + IPv6, peer-reflexive
// candidates, role conflict resolution.
//
// Usage:
//   import { IceAgent } from 'turn-server';
//
//   let agent = new IceAgent({
//     iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
//     mode: 'full',            // 'full' | 'lite'
//     trickle: true,
//     controlling: true,
//   });
//
//   agent.on('candidate', (c) => { /* null = end-of-candidates */ });
//   agent.on('statechange', (next, prev) => {});
//   agent.on('selectedpair', (pair) => {});
//   agent.on('packet', (buf, rinfo) => { /* non-STUN: DTLS/RTP/RTCP */ });
//
//   agent.setRemoteParameters({ ufrag, pwd });
//   agent.addRemoteCandidate(candObj);
//   agent.addRemoteCandidate(null);   // end-of-candidates
//   agent.gather();                    // fire-and-forget; events flow via 'candidate'
//
//   // SDP layer reads:   agent.localParameters  →  { ufrag, pwd, iceLite }
//   //                    agent.context.localCandidates
//
// The set_context pattern (see tls_session / order for reference) drives
// all state transitions reactively. External code may call set_context()
// directly or use the convenience methods.

import { randomBuffer } from './random.js';
import dgram from 'node:dgram';
import os from 'node:os';
import { EventEmitter } from 'node:events';
import * as wire from './wire.js';
// Socket (TURN client) is imported lazily inside gatherRelayCandidate
// to keep host/srflx gathering usable without the full TURN dependencies.
import {
  computeCandidatePriority,
  computePairPriority,
  computeFoundation,
  formatCandidate,
  parseCandidate,
  addressFamilyOf,
  candidateKey,
  pairKey,
  isMdnsHost,
  isResolvableMdnsCandidate,
} from './ice_candidate.js';
import * as iceMdns from './ice_mdns.js';
import { checkedSocketBufferSize, udpSocketOptions } from './udp_buffers.js';
import * as icePortmap from './ice_portmap.js';


/* ========================= Constants ========================= */

// ICE states — RFC 8445 §6.1.4 (connection state)
// new, checking, connected, completed, disconnected, failed, closed
const ICE_STATES = ['new', 'checking', 'connected', 'completed', 'disconnected', 'failed', 'closed'];
const GATHERING_STATES = ['new', 'gathering', 'complete'];

// (Type preferences live in ice-candidate.js.)

// ── Full ICE: connectivity checks the way libwebrtc runs them ──
//
// Chrome is the peer that matters, and its ICE departs from the RFC-shaped
// scheduler this agent had (RFC 5389 retransmissions, one-shot regular
// nomination, a separate 15s consent cycle) in ways peers notice: it keeps
// checking new pairs after it connects and moves to a better one, it learns
// a path died within seconds, not 30-45. The values below are libwebrtc's
// own (p2p/base/p2p_constants.h, connection.cc, basic_ice_controller.cc).
//
// Every check is a NEW transaction — never a retransmission of the same
// bytes (a retransmission repeats the role it was sent with, the deadlock
// the 487 fix had to untangle); a response is accepted for up to 60s.
const PING_WEAK_MS               = 48;     // kWeakPingInterval: while nothing works, or a pair's first 3 checks
const PING_STRONG_MS             = 480;    // kStrongPingInterval: the scheduler's pace once connected
const PING_STABLE_WRITABLE_MS    = 2500;   // a working pair, RTT settled, nothing missing
const PING_UNSTABLE_WRITABLE_MS  = 900;    // a working pair otherwise
const PING_BACKUP_MS             = 25000;  // working pairs that are not the selected one
const MIN_PINGS_AT_WEAK          = 3;      // kMinPingsAtWeakPingInterval
const CHECK_RECEIVING_MS         = 250;    // the scheduler wakes at least this often (state upkeep)
const RECEIVING_TIMEOUT_MS       = 2500;   // nothing received this long → not receiving
const RECEIVING_SWITCH_DELAY_MS  = 1000;   // a receiving difference counts once it held this long
const UNWRITABLE_TIMEOUT_MS      = 5000;   // working → unreliable: unanswered this long ...
const UNWRITABLE_MIN_CHECKS      = 5;      // ... and this many checks
const INACTIVE_TIMEOUT_MS        = 15000;  // unanswered this long → the pair is dead (timeout)
const RESPONSE_TIMEOUT_MS        = 60000;  // a late response is still accepted this long
const DEFAULT_RTT_MS             = 3000;   // before the first measurement
const MIN_RTT_MS                 = 100;
const MAX_RTT_MS                 = 60000;
const RTT_RATIO                  = 3;      // smoothing: rtt = (3·rtt + sample) / 4
// RFC 8863 §4: the PAC timer, "equal to the agent's connectivity check
// transaction timeout, including all retransmissions" — this agent gives a
// check up after INACTIVE_TIMEOUT_MS unanswered (libwebrtc's write timeout),
// not RFC 5389's 39.5 s of Rc retransmissions at the default RTO.
const PAC_TIMEOUT_MS             = 15000;
const MIN_RTT_IMPROVEMENT_MS     = 10;     // kMinImprovement: an RTT-only switch must gain this

// ── [ice-diag] instrumentation gate + rate limiter ──
// Enabled with WEBRTC_DEBUG=1 (same env var the webrtc-server layers use).
// _diagRL(key, ms) returns true at most once per `ms` per key — lets us
// log recurring hot-path events (binding responses, consent ticks)
// without flooding.
const _ICE_DBG = (typeof process !== 'undefined' && process.env &&
                  (process.env.WEBRTC_DEBUG === '1' || process.env.WEBRTC_DEBUG === 'true'));
const _diagRLState = {};
function _diagRL(key, ms) {
  if (!_ICE_DBG) return false;
  const now = Date.now();
  if (_diagRLState[key] && (now - _diagRLState[key]) < ms) return false;
  _diagRLState[key] = now;
  return true;
}
function _diagTs() { return new Date().toISOString().slice(11, 23); }
// Every [ice-diag] line goes through here. Several of them (socket
// bound/closed, role/ufrag set via opts, ICE STATE, restart) used to call
// console.log directly and printed on every connection without
// WEBRTC_DEBUG. Callers that build expensive strings still check _ICE_DBG
// first; this is the gate that cannot be forgotten.
function _diagLog() {
  if (_ICE_DBG) console.log.apply(console, arguments);
}

// Lite liveness (passive): a full-ICE peer checks its selected pair at least
// every few seconds (Chrome 2.5s, RFC 7675 consent every 4-6s — Firefox), so
// silence is the signal. Disconnected after 15s without a check (two to
// three missed consent checks — tighter would flap on RFC 7675 peers),
// failed at 30s (RFC 7675: consent expires after 30 seconds).
const LITE_DISCONNECT_MS        = parseInt(process.env.ICE_LITE_DISCONNECT_MS || '15000', 10);
const LITE_FAILED_MS            = parseInt(process.env.ICE_LITE_FAILED_MS     || '30000', 10);
// Lite liveness (passive) — how often the observer wakes to read the
// last-request age. The THRESHOLDS are deliberately the consent ones:
// disconnected/failed mean the same thing regardless of which side's
// evidence proved the path dead.
const LITE_LIVENESS_TICK_MS     = parseInt(process.env.ICE_LITE_LIVENESS_TICK_MS || '5000', 10);
// Lite: a pair is "receiving" while the peer's checks keep arriving on it —
// libwebrtc's receiving timeout (kReceivingTimeout, 2.5s). Decides whether
// the selected pair is still the path the peer uses (cascade 2.5).
const LITE_RECEIVING_MS         = 2500;

// Gathering — global safety cap
const GATHER_SRFLX_TIMEOUT_MS = 5000;
const GATHER_RELAY_TIMEOUT_MS = 8000;

// TURN permission — RFC 5766 §8 — 5 min default, refresh at 4 min
const TURN_PERMISSION_LIFETIME_MS = 300000;
const TURN_PERMISSION_REFRESH_MS = 240000;

// Component ID — we always use 1 (RTCP-mux for WebRTC; SIP may differ)
const COMPONENT_RTP = 1;

// Local preference — single address family gets 65535; when we have multiple
// families we could differentiate but for now this is fine (RFC 8445 §5.1.2.1).
const LOCAL_PREFERENCE_DEFAULT = 65535;


/* ========================= Helpers ========================= */

function randomUfrag() {
  // RFC 8445 §16.1 + RFC 5245 §15.1:
  //   ufrag ≥ 4 characters of ice-char = ALPHA / DIGIT / "+" / "/"
  // 3 random bytes → 4 base64 chars (with 2 '=' padding, which we strip).
  return randomBuffer(3).toString('base64').replace(/=/g, '');
}

function randomPwd() {
  // RFC 8445 §16.1: password ≥ 128 bits of randomness = ≥ 22 ice-chars
  // 16 random bytes → 24 base64 chars (2 '=' padding); after stripping = 22 chars.
  // NOTE: ice-char includes '+' and '/', so we do NOT strip those.
  return randomBuffer(16).toString('base64').replace(/=/g, '');
}

function txIdHex(txnId) {
  if (!txnId) return '';
  let s = '';
  for (let i = 0; i < txnId.length; i++) s += (txnId[i] < 16 ? '0' : '') + txnId[i].toString(16);
  return s;
}

function parseIceServerUri(urls) {
  // urls can be a string or array; we take the first URI here
  let uri = Array.isArray(urls) ? urls[0] : urls;
  if (!uri) return null;
  let parsed = wire.parseUri(uri);
  if (parsed) return parsed;

  // Fallback: simple 'host:port' or 'scheme:host:port'.
  // Scheme matching is case-insensitive (RFC 3986 §3.1) — mirrored from
  // wire.parseUri's contract so both paths agree.
  let m = uri.match(/^(stun|stuns|turn|turns):(?:\/\/)?([^:?\/]+)(?::(\d+))?/i);
  if (!m) return null;
  const _scheme = m[1].toLowerCase();
  return {
    scheme: _scheme,
    isTurn: _scheme === 'turn' || _scheme === 'turns',
    secure: _scheme.endsWith('s'),
    host: m[2].toLowerCase(),
    port: m[3] ? parseInt(m[3], 10) : 3478,
    transport: 'udp',
  };
}


/* ========================= Candidate formatting ========================= */
// (formatCandidate / parseCandidate live in ice-candidate.js — imported above.)


/* ========================= IceAgent ========================= */

function IceAgent(options) {
  if (!(this instanceof IceAgent)) return new IceAgent(options);
  options = options || {};

  // ── External socket validation ──
  // When running on a shared UDP port (server-side ICE Lite scenario),
  // the caller provides a pre-bound dgram.Socket via options.socket
  // (IPv4) and/or options.socket6 (IPv6). Sockets MUST be bound before
  // being passed — we validate this immediately so errors surface early.
  if (options.socket) {
    try { options.socket.address(); }
    catch (e) { throw new Error('options.socket must be bound before new IceAgent()'); }
  }
  if (options.socket6) {
    try { options.socket6.address(); }
    catch (e) { throw new Error('options.socket6 must be bound before new IceAgent()'); }
  }

  const hasExternal = !!(options.socket || options.socket6);

  // Default mode: 'lite' when using shared socket (server scenario),
  // 'full' otherwise (client scenario). Explicit options.mode wins.
  const resolvedMode = options.mode === 'lite' ? 'lite' :
                       options.mode === 'full' ? 'full' :
                       (hasExternal ? 'lite' : 'full');

  // ICE Lite MUST be controlled (RFC 8445 §6.1.1). In 'full' mode, default
  // to controlling (offerer role). Explicit options.controlling wins.
  const resolvedControlling = options.controlling !== undefined ? !!options.controlling :
                              (resolvedMode === 'lite' ? false : true);

  // ── mDNS candidates (draft-ietf-mmusic-mdns-ice-candidates) ──
  //
  //   options.mdns:
  //     false / undefined  — no mDNS. Inbound ".local" candidates are
  //                          DROPPED (never handed to dgram.send(), whose
  //                          per-call getaddrinfo made behavior differ by
  //                          OS and flooded the libuv threadpool).
  //     true               — resolve inbound ".local" candidates.
  //     { resolve, register, instance, module, mdnsOptions,
  //       timeout, unicast }
  //         resolve   default true when mdns is enabled
  //         register  default false — conceal OUR host candidates behind
  //                   UUID ".local" names (privacy clients: Electron/P2P).
  //                   Never useful on servers; lite mode ignores it.
  //         instance / module / mdnsOptions / timeout / unicast — passed
  //                   to ice_mdns.acquire() (see src/ice_mdns.js).
  //
  // Shaped as a per-source config (not one boolean) so future gathering
  // sources (e.g. a port-mapper/UPnP source) can sit beside it without
  // reshaping the public API.
  // ── Port-mapping assisted gathering (UPnP-IGD / NAT-PMP / PCP) ──
  //
  //   options.portMapping:
  //     false / undefined — off. (webrtc-server turns this on for full-mode
  //                         clients; at the agent layer — mechanism, not
  //                         policy — nothing talks to the router unasked.)
  //     true              — map each host base on the gateway and advertise
  //                         the external address as an srflx candidate.
  //     { instance, instance6, module, description, lifetime, timeout,
  //       mapperOptions } — passed to ice_portmap.acquire().
  //
  // Ignored entirely in lite mode and under iceTransportPolicy 'relay'
  // (same reasoning as srflx: lite gathers host-only; relay forbids both).
  const _pmOpt = options.portMapping;
  const resolvedPortMapping = {
    enabled: !!_pmOpt && resolvedMode !== 'lite',
    options: (typeof _pmOpt === 'object' && _pmOpt) ? {
               instance:      _pmOpt.instance,
               instance6:     _pmOpt.instance6,
               module:        _pmOpt.module,
               description:   _pmOpt.description,
               lifetime:      _pmOpt.lifetime,
               timeout:       _pmOpt.timeout,
               mapperOptions: _pmOpt.mapperOptions,
             } : {},
  };

  const _mdnsOpt = options.mdns;
  const resolvedMdns = {
    resolve:  !!_mdnsOpt && (typeof _mdnsOpt !== 'object' || _mdnsOpt.resolve !== false),
    register: !!(_mdnsOpt && typeof _mdnsOpt === 'object' && _mdnsOpt.register === true
                 && resolvedMode !== 'lite'),
    options:  (typeof _mdnsOpt === 'object' && _mdnsOpt) ? {
                instance:    _mdnsOpt.instance,
                module:      _mdnsOpt.module,
                mdnsOptions: _mdnsOpt.mdnsOptions,
                timeout:     _mdnsOpt.timeout,
                unicast:     _mdnsOpt.unicast,
              } : {},
  };

  const ev = new EventEmitter();
  const self = this;


  /* ====================== Context ====================== */

  let context = {

    // ── Identity & config ──
    mode:                 resolvedMode,
    trickle:              options.trickle !== false,            // default true
    controlling:          resolvedControlling,
    iceServers:           options.iceServers || [],
    iceTransportPolicy:   options.iceTransportPolicy || 'all',   // 'all' | 'relay' — for the NEXT gathering phase
    // The policy of the current gathering phase (RFC 9429 §3.5.3: "determine
    // the current setting at the start of each gathering phase"). Latched by
    // beginPhase() — at the first gather() and at the first gather() after
    // restart() — so setConfiguration() changes nothing mid-phase.
    phasePolicy:          options.iceTransportPolicy || 'all',
    includeLoopback:      !!options.includeLoopback,
    ipv6:                 options.ipv6 !== false,                // default true
    portRange:            options.portRange || [0, 0],           // [min, max]; 0 = any
    // The buffers of the UDP sockets this agent binds (udp_buffers.js):
    // 4 MB by default; 0 or false for the OS's. Not applied to a socket
    // the caller hands in (options.socket / socket6) — that one is theirs.
    socketBufferSize:     checkedSocketBufferSize(options.socketBufferSize, 'IceAgent: socketBufferSize'),
    components:           options.components || 1,
    tieBreaker:           randomBuffer(8),

    // ── mDNS (draft-ietf-mmusic-mdns-ice-candidates) runtime state ──
    mdns: {
      resolve:         resolvedMdns.resolve,
      register:        resolvedMdns.register,
      options:         resolvedMdns.options,
      handle:          null,   // acquired ice_mdns handle (refcounted, shared)
      acquiring:       null,   // [cb, ...] while acquire() is in flight
      pendingResolves: 0,      // in-flight inbound resolutions — gates 'failed'
      registeredIps:   [],     // OUR ips registered outbound (teardown cleanup)
    },
    _gathering_mdns_reg: 0,    // outbound registrations in flight — gates
                               // gatheringState 'complete'

    // ── Port-mapping runtime state ──
    portmap: {
      enabled:     resolvedPortMapping.enabled,
      options:     resolvedPortMapping.options,
      handle:      null,   // acquired ice_portmap handle
      mappedPorts: [],     // [{ port, family }] — teardown cleanup
      errorOnce:   false,  // dead-gateway/CGNAT reported once, not per base
    },
    _gathering_portmap: 0,     // mappings in flight — gates 'complete'

    // ── State (scalar, equality + emit inline) ──
    state:                'new',
    gatheringState:       'new',
    closed:               false,

    // ── Parameters (set-once until restart) ──
    localUfrag:           options.ufrag || null,
    localPwd:             options.pwd   || null,
    remoteUfrag:          null,
    remotePwd:            null,
    remoteIceLite:        false,

    // ── Candidates ──
    localCandidates:      [],    // array, merged via addLocalCandidate
    remoteCandidates:     [],    // array, merged via addRemoteCandidate
    remoteCandidatesEnded: false,

    // ── Check list / pairs ──
    checkList:            [],
    validList:            [],

    // ── Selected pair ──
    selectedPair:         null,

    // ── Sockets ──
    sockets:              {},    // key 'family:ip:port' → dgram.Socket
    primarySocket:        null,  // preferred socket for sending (set by selection)
    externalSocket:       options.socket  || null,  // externally-provided IPv4 socket
    externalSocket6:      options.socket6 || null,  // externally-provided IPv6 socket

    // ── ICE-TCP, passive (RFC 6544) — lite servers only ──
    // Objects shaped like a dgram socket — address() and send(buf, port, ip,
    // cb) — that carry ICE over TCP connections someone else accepts (e.g.
    // WebRTCRouter.tcp()). When present, every host address also gets a
    // 'tcp … tcptype passive' candidate, below UDP in priority. Packets from
    // those connections come in through handlePacket() with rinfo.protocol
    // 'tcp'; replies and media go back through send().
    tcpSocket:            options.tcpSocket  || null,
    tcpSocket6:           options.tcpSocket6 || null,

    // ── Announced addresses — override host candidate IPs/ports.
    // Useful when the bind address ≠ public address (NAT, cloud, 0.0.0.0 bind).
    // Each entry is either a string (IP) or { ip, port }. When omitted, falls
    // back to reading socket.address() as before.
    announcedAddresses:   options.announcedAddresses || null,

    // ── TURN clients (for relay candidates) ──
    turnClients:          {},    // key 'host:port' → turn Socket
    turnPermissions:      {},    // key 'turnKey|peerIp' → { expires, timer }

    // ── STUN transactions ──
    pendingTransactions:  {},    // txnIdHex → { kind: 'check'|'consent'|'gather-srflx', pair?, timer?, callback }

    // ── Full ICE check scheduler (bookkeeping — not cascade state) ──
    pingTimer:            null,   // the scheduler's next wake-up (pingTick)
    pingDueAt:            0,      // when it is due
    lastPingAt:           0,      // last check sent, any pair (pacing)
    lastTxSweepAt:        0,      // last expiry sweep of check transactions
    hasBeenWritable:      false,  // a selected pair worked once → losing it is 'disconnected'

    // ── State tracked by set_context cascades ──
    selectedPair:         null,   // when set → cascade: emit, state=connected
    // ── Lite liveness (passive; RFC-8445 §11 keepalives as evidence) ──
    // Consent (RFC 7675) is a SENDER's mechanism and cascade 2.8 rightly
    // skips it in lite — but that left lite with NO producer of
    // 'disconnected' at all: a vanished peer stayed 'connected' forever
    // (found live: an SFU recv transport whose browser tab refreshed kept
    // sending RTP into the void indefinitely). The full-ICE peer is
    // REQUIRED to send keepalive binding requests on the live pair
    // (RFC 8445 §11, "MUST ... regardless of whether the data stream is
    // currently inactive"), so their absence IS the liveness signal —
    // observed, never transmitted: zero bytes on the wire from us.
    liteLivenessTimer:    null,   // bookkeeping (rule at 'Timer handles')
    liteLivenessActive:   false,  // cycle running
    lastRequestReceivedAt: 0,     // any AUTHENTICATED binding request

    // ── ICE restart — RFC 8445 §9 ──
    // During a restart, the PREVIOUS selectedPair keeps forwarding media
    // until the new session picks its own winner. _previousPair preserves
    // that old pair for send() continuity; it's cleared when the new
    // selectedPair is chosen (cascade 2.5).
    _previousPair:        null,

    // ── Internal guards (mutated directly) ──
    _gathering_host:      false,
    _gathering_srflx:     0,
    _gathering_relay:     0,
    _endOfCandidatesEmitted: false,
    _reopenAfterFailed: false,     // a remote candidate arrived after 'failed' (cascade 2.0)
    _reEmitOnGather:      false,   // set by restart(): re-announce kept candidates
    _phasePending:        true,
    pacStartedAt:         0,       // RFC 8863 PAC timer: when the session's checks could start
    pacTimer:             null,    // bookkeeping: re-evaluates a pair-less session at expiry    // the next startGathering() begins a phase (beginPhase)
    _gather_timers:       new Set(),
  };

  // Auto-generate credentials if not supplied
  if (!context.localUfrag) context.localUfrag = randomUfrag();
  if (!context.localPwd)   context.localPwd   = randomPwd();


  /* ====================== set_context ====================== */
  //
  // Central reactive setter — all ICE state transitions flow through here.
  //
  //  Phase 1: Per-field updates with equality check + inline emit
  //  Phase 2: Reactive cascades — detect conditions, derive new state,
  //           collect into params_to_set, recurse.
  //
  // "Notification" fields that always set has_changed=true (signal events):
  //    add_local_candidate, add_remote_candidate, pair_validated, pair_failed
  //
  // Timer handles (pingTimer, liteLivenessTimer) are bookkeeping, mutated
  // imperatively alongside the state that DOES cascade.

  function set_context(opts) {
    if (!opts || typeof opts !== 'object') return;
    // Once closed, ignore further mutations except the terminal state transition.
    if (context.closed && opts.state !== 'closed' && opts.closed !== true) return;

    let has_changed = false;


    /* ─────────── Phase 1: per-field ─────────── */

    /* Config (set-once; rarely mutated) */

    if ('mode' in opts) {
      if (opts.mode !== context.mode && (opts.mode === 'full' || opts.mode === 'lite')) {
        context.mode = opts.mode;
        has_changed = true;
      }
    }

    if ('trickle' in opts) {
      if (opts.trickle !== context.trickle) {
        context.trickle = !!opts.trickle;
        has_changed = true;
      }
    }

    if ('controlling' in opts) {
      if (opts.controlling !== context.controlling) {
        if (context.controlling !== !!opts.controlling) {
          _diagLog('[ice-diag] ' + _diagTs() + ' ROLE SET via opts: ' +
                      context.controlling + ' → ' + !!opts.controlling);
        }
        context.controlling = !!opts.controlling;
        has_changed = true;
        // Role change → recompute pair priorities + re-sort
        recomputePairPriorities();
        ev.emit('rolechange', context.controlling ? 'controlling' : 'controlled');
      }
    }

    if ('announcedAddresses' in opts) {
      if (opts.announcedAddresses !== context.announcedAddresses) {
        context.announcedAddresses = opts.announcedAddresses;
        has_changed = true;
      }
    }


    /* Credentials */

    let _localCredsChanged = false;

    if ('localUfrag' in opts) {
      if (opts.localUfrag !== context.localUfrag && opts.localUfrag) {
        _diagLog('[ice-diag] ' + _diagTs() + ' localUfrag set via opts: ' +
                    context.localUfrag + ' → ' + opts.localUfrag);
        context.localUfrag = opts.localUfrag;
        has_changed = true;
        _localCredsChanged = true;
      }
    }

    if ('localPwd' in opts) {
      if (opts.localPwd !== context.localPwd && opts.localPwd) {
        context.localPwd = opts.localPwd;
        has_changed = true;
        _localCredsChanged = true;
      }
    }

    // Local credentials changed (e.g. setLocalParameters overriding the ones
    // restart() generated). Routers indexing agents by ufrag MUST hear about
    // this — the 'restart' event alone carries the agent's own generated
    // creds, which the SDP layer may immediately replace with its own.
    if (_localCredsChanged) {
      ev.emit('localparameters', { ufrag: context.localUfrag, pwd: context.localPwd });
    }

    if ('remoteUfrag' in opts) {
      if (opts.remoteUfrag !== context.remoteUfrag && opts.remoteUfrag) {
        context.remoteUfrag = opts.remoteUfrag;
        has_changed = true;
      }
    }

    if ('remotePwd' in opts) {
      if (opts.remotePwd !== context.remotePwd && opts.remotePwd) {
        context.remotePwd = opts.remotePwd;
        has_changed = true;
        // RFC 8863 §4: the PAC timer starts once the checks can start (our
        // credentials sent, the peer's received).
        if (!context.pacStartedAt) context.pacStartedAt = Date.now();
      }
    }

    if ('remoteIceLite' in opts) {
      if (!!opts.remoteIceLite !== context.remoteIceLite) {
        context.remoteIceLite = !!opts.remoteIceLite;
        has_changed = true;
        // If remote is lite, we MUST be controlling (RFC 8445 §6.1.1)
        if (context.remoteIceLite && !context.controlling) {
          context.controlling = true;
          recomputePairPriorities();
          ev.emit('rolechange', 'controlling');
        }
      }
    }


    /* Lifecycle state (emits inline on change) */

    if ('state' in opts) {
      if (opts.state !== context.state && ICE_STATES.indexOf(opts.state) >= 0) {
        const prev = context.state;
        context.state = opts.state;
        has_changed = true;
        // [ice-diag] agent-side state transitions with precise timestamps —
        // lets us line up the server's view against the browser's timeline.
        if (_ICE_DBG) {
          _diagLog('[ice-diag] ' + _diagTs() + ' ICE STATE ' + prev + ' → ' + context.state);
        }
        ev.emit('statechange', context.state, prev);
      }
    }

    if ('gatheringState' in opts) {
      if (opts.gatheringState !== context.gatheringState && GATHERING_STATES.indexOf(opts.gatheringState) >= 0) {
        const prev = context.gatheringState;
        context.gatheringState = opts.gatheringState;
        has_changed = true;
        ev.emit('gatheringstatechange', context.gatheringState, prev);
      }
    }

    if ('closed' in opts && opts.closed === true && !context.closed) {
      context.closed = true;
      has_changed = true;
    }


    /* Candidate merge (add-by-key) */

    if ('add_local_candidate' in opts) {
      const cand = opts.add_local_candidate;
      if (cand && localUsable(cand) && !findLocalCandidate(cand.ip, cand.port, cand.protocol || 'udp')) {
        context.localCandidates.push(cand);
        has_changed = true;
        // RFC 8838 — Trickle ICE: emit candidates as found.
        // Non-trickle (legacy) mode: batch all candidates until gathering
        // completes, then emit them all at once via cascade 2.1.
        if (context.trickle) {
          ev.emit('candidate', maskCandidateForSignaling(cand));
        }
        formPairsForNewLocal(cand);   // may push new pairs to checkList
      }
    }

    if ('add_remote_candidate' in opts) {
      const cand = opts.add_remote_candidate;
      if (cand === null) {
        // end-of-candidates signal
        if (!context.remoteCandidatesEnded) {
          context.remoteCandidatesEnded = true;
          has_changed = true;
        }
      } else if (cand && isMdnsHost(cand.ip)) {
        // ".local" concealment name — NEVER treat as a literal address.
        // Resolution (or drop) happens here, before pair formation, so
        // candidateKey / findRemoteCandidate always operate on the final
        // IP and pair keys never contain hostnames. Re-entry with the
        // resolved candidate lands in the plain branch below; the replay
        // buffer re-sending the same ".local" candidate is harmless — the
        // second resolution is a cache hit and the resolved (ip, port)
        // dedups normally.
        handleMdnsRemoteCandidate(cand);
      } else if (cand && !findRemoteCandidate(cand.ip, cand.port)) {
        context.remoteCandidates.push(cand);
        has_changed = true;
        const pairsBefore = context.checkList.length;
        formPairsForNewRemote(cand);
        // A candidate trickled in after 'failed' (RFC 8838 §8: the peer had
        // not signalled end-of-candidates, so the check list was never
        // complete). 'failed' used to latch until a restart, so a path that
        // arrived a little late could never be used. Reopen the session
        // for the new pairs, as Chrome does (failed → checking); cascade
        // 2.0 does it, once per set_context pass.
        if (context.state === 'failed' && context.mode !== 'lite' &&
            context.checkList.length > pairsBefore) {
          context._reopenAfterFailed = true;
        }
      } else if (cand) {
        // A SIGNALLED CANDIDATE OUTRANKS A DISCOVERED ONE.
        //
        // We may already hold this (ip, port) as PEER-REFLEXIVE, learned from
        // an incoming binding request before the peer's signalling arrived —
        // a normal race, since checks start as soon as the first candidate
        // lands. The duplicate guard then dropped the signalled copy, and the
        // entry stayed 'prflx' forever.
        //
        // That loses real information. RFC 8445 5.1.2: peer-reflexive means
        // "discovered, never announced", and the API contract depends on it —
        // getRemoteCandidates() returns what the peer TOLD us and correctly
        // omits prflx, so it returned an empty list for a connection whose
        // peer had signalled a perfectly good host candidate.
        //
        // Upgrade in place: keep the object (pairs and the check list point at
        // it) and adopt the signalled type, foundation and priority, which are
        // the peer's own values rather than our guesses.
        const known = findRemoteCandidate(cand.ip, cand.port);
        if (known && known.type === 'prflx' && cand.type && cand.type !== 'prflx') {
          known.type = cand.type;
          if (cand.foundation != null) known.foundation = cand.foundation;
          if (cand.priority != null)   known.priority   = cand.priority;
          if (cand.relatedAddress != null || cand.raddr != null) {
            known.relatedAddress = cand.relatedAddress != null ? cand.relatedAddress : cand.raddr;
          }
          if (cand.relatedPort != null || cand.rport != null) {
            known.relatedPort = cand.relatedPort != null ? cand.relatedPort : cand.rport;
          }
          // Its pairs' priorities follow the candidate's (RFC 8445 §6.1.2.3)
          // — kept at the guessed prflx priority, a pair the peer ranks
          // higher could never win the selection.
          if (cand.priority != null) recomputePairPriorities();
          has_changed = true;
        }
      }
    }


    /* Pair events — notifications that always trigger cascade */

    if ('pair_validated' in opts) {
      const p = opts.pair_validated;
      if (p) {
        has_changed = true;   // always cascade — pair state may have changed nomination-wise
        if (context.validList.indexOf(p) < 0) context.validList.push(p);
        ev.emit('paircheck', p, true);
      }
    }

    if ('pair_failed' in opts) {
      const p = opts.pair_failed;
      if (p) {
        has_changed = true;
        ev.emit('paircheck', p, false);
      }
    }

    // Triggered-check enqueued notification — sent by handleBindingRequest
    // when a pair was enqueued for a triggered check. Forces cascade re-run
    // without mutating actual state.
    if ('pair_triggered' in opts) {
      if (opts.pair_triggered) has_changed = true;
    }

    // Full ICE scheduler tick — pair states moved with time; re-run the
    // selection and state cascades.
    if ('pair_tick' in opts) {
      if (opts.pair_tick) has_changed = true;
    }


    /* Selected pair (emits inline) */

    if ('selectedPair' in opts) {
      if (opts.selectedPair !== context.selectedPair) {
        const prev = context.selectedPair;
        context.selectedPair = opts.selectedPair;
        has_changed = true;
        if (context.selectedPair) {
          // Track socket for direct sends (relay pairs use turnClient instead)
          const sock = getSocketForLocalCandidate(context.selectedPair.local);
          if (sock && !context.selectedPair.local.turnClient) context.primarySocket = sock;
          ev.emit('selectedpair', context.selectedPair, prev || null);
        }
      }
    }


    /* Internal replace-only */

    if ('primarySocket' in opts) {
      if (opts.primarySocket !== context.primarySocket) {
        context.primarySocket = opts.primarySocket;
        has_changed = true;
      }
    }

    if ('externalSocket' in opts) {
      context.externalSocket = opts.externalSocket;
      has_changed = true;
    }

    if ('externalSocket6' in opts) {
      context.externalSocket6 = opts.externalSocket6;
      has_changed = true;
    }


    /* ─────────── Phase 2: reactive cascades ─────────── */

    if (has_changed !== true) return;

    const params_to_set = {};


    /* 2.1 — Gathering complete: emit candidates + end-of-candidates.
     *  In trickle mode, individual candidates were already emitted as they
     *  were gathered (see add_local_candidate handler above). We only need
     *  to emit the null terminator.
     *  In non-trickle (vanilla) mode, we batched everything — emit all
     *  candidates now in priority order, then the null terminator. */
    if (context.gatheringState === 'complete' && !context._endOfCandidatesEmitted) {
      context._endOfCandidatesEmitted = true;
      if (!context.trickle) {
        const batch = context.localCandidates.filter(localUsable).sort(function(a, b) {
          return b.priority - a.priority;
        });
        for (let i = 0; i < batch.length; i++) ev.emit('candidate', maskCandidateForSignaling(batch[i]));
      }
      ev.emit('candidate', null);
    }


    /* 2.0 — Full ICE: a remote candidate arrived after 'failed' and formed
     *  new pairs (see add_remote_candidate). Leave 'failed' so the scheduler
     *  (2.2) starts again; the recursive pass applies the state first. A
     *  path that once worked reports 'disconnected', like computeFullState. */
    if (context._reopenAfterFailed) {
      context._reopenAfterFailed = false;
      if (context.state === 'failed' && !context.closed) {
        set_context({ state: context.hasBeenWritable ? 'disconnected' : 'checking' });
        return;
      }
    }


    /* 2.2 — Full ICE: start the check scheduler once there is something to
     *  check — credentials and at least one pair. It then runs for the life
     *  of the session (selected-pair keepalives ARE checks, as in libwebrtc;
     *  there is no separate consent cycle), until failed, a restart or
     *  close. pingTick drives everything time-based: pair states, the
     *  selected pair, pruning, the connection state. */
    if (context.mode !== 'lite' &&
        !context.pingTimer &&
        context.state !== 'failed' &&
        context.remoteUfrag && context.remotePwd &&
        context.checkList.length > 0 &&
        !context.closed) {
      schedulePingTick(0);
    }


    /* 2.5 — The selected pair.
     *
     * Lite: the highest-priority nominated valid pair, then following the
     * path the peer actually uses (below).
     *
     * Full: libwebrtc's comparator (fullSelect) — a working pair over one
     * that is not, receiving over not, then (controlled side) nominated,
     * then priority; an RTT-only switch must gain 10ms. Also re-run on every
     * scheduler tick, so a pair that starts or stops working moves the
     * selection without waiting for an event. */
    if (!context.closed) {
      let best = context.selectedPair || null;
      if (context.mode === 'lite' && best) {
        // LITE FOLLOWS THE PATH THE PEER IS USING.
        //
        // A lite agent never checks, so the controlling peer decides the
        // path alone and says so with USE-CANDIDATE — libwebrtc, facing a
        // lite peer, puts it on the pings of its SELECTED pair only. When
        // it moves (its network changed: a relay pair now), USE-CANDIDATE
        // arrives on another pair; the old one, possibly of higher
        // priority, goes quiet. Highest-priority-nominated alone kept us on
        // that dead path — sending media to an address the peer no longer
        // reads.
        //
        // Switch to a pair the peer is checking right now (receiving) and
        // nominated after the selected one's last nomination; while the
        // selected pair is still receiving, only to a higher-priority one
        // (an aggressive-nomination peer converging, as before). The
        // nomination-order guard keeps a backup ping (no USE-CANDIDATE) on
        // an old pair from pulling us back to it.
        const now = Date.now();
        const sel = best;
        const selReceiving = (now - sel.requestReceivedAt) < LITE_RECEIVING_MS;
        for (let i = 0; i < context.validList.length; i++) {
          const p = context.validList[i];
          if (p === sel || !p.valid || !p.nominated) continue;
          if ((now - p.requestReceivedAt) >= LITE_RECEIVING_MS) continue;
          if (p.nominatedAt <= sel.nominatedAt) continue;
          if (selReceiving) {
            if (p.priority > best.priority) best = p;
          } else if (best === sel || p.nominatedAt > best.nominatedAt) {
            best = p;
          }
        }
      } else if (context.mode === 'lite') {
        for (let i = 0; i < context.validList.length; i++) {
          const p = context.validList[i];
          if (!p.valid || !p.nominated) continue;
          if (!best || p.priority > best.priority) best = p;
        }
      } else {
        best = fullSelect(Date.now()) || context.selectedPair || null;
      }
      if (best && best !== context.selectedPair) {
        params_to_set.selectedPair = best;
        // ICE restart complete — drop the previous pair; new selectedPair
        // (assigned by the recursive set_context call) takes over send().
        if (context._previousPair) {
          context._previousPair = null;
          releaseRetiredRelays(best);
        }
      }
    }


    /* 2.6 — The connection state.
     *
     * Lite: 'connected' once selected; the passive liveness (2.8b) owns
     * 'disconnected' / 'failed'.
     *
     * Full: derived from the pairs, as libwebrtc does
     * (ComputeIceTransportState) — see computeFullState. */
    if (context.mode === 'lite') {
      // 'disconnected' is excluded alongside 'failed' and 'closed': it is the
      // liveness verdict, and the pair is still selected — without this
      // exclusion every set_context({state:'disconnected'}) was undone by the
      // very cascade run it triggered. Recovery is owned by liteLivenessTick.
      if (context.selectedPair &&
          context.state !== 'connected' &&
          context.state !== 'disconnected' &&
          context.state !== 'failed' &&
          context.state !== 'closed') {
        params_to_set.state = 'connected';
      }
    } else if (!('state' in params_to_set) && !('selectedPair' in params_to_set)) {
      // Not in the same pass as a new selected pair: set_context emits the
      // state before it applies selectedPair, and 'connected' is the cue
      // the SDP layer starts DTLS on — synchronously. Its first flight then
      // went out through send() with no selected pair yet and was dropped;
      // the handshake waited out DTLS's 1s retransmission. The recursive
      // pass that applies the pair decides the state, right after.
      const st = computeFullState(context.selectedPair);
      if (st && st !== context.state) params_to_set.state = st;
    }


    /* 2.8b — Lite: passive liveness (see the context-field note). Gated on
     * liteLivenessActive, NOT the timer handle — the handle is null for the
     * duration of a tick, and a state change made inside the tick would
     * otherwise look like "not running" and restart the cycle, erasing the
     * very evidence that produced the change. */
    if (context.selectedPair &&
        !context.liteLivenessActive &&
        context.mode === 'lite' &&
        !context.closed) {
      initiateLiteLiveness();       // imperative: schedules first liveness tick
    }


    /* 2.9 — Terminal close: run teardown and settle state=closed */
    if (context.closed && context.state !== 'closed') {
      teardown();   // imperative: clear all timers/sockets
      params_to_set.state = 'closed';
    }


    /* ─────────── Recurse ─────────── */

    if (Object.keys(params_to_set).length > 0) {
      set_context(params_to_set);
    }
  }


  /* ========================= Candidate lookup ========================= */

  // protocol: as findRemoteCandidate — a UDP and a TCP candidate on the same
  // ip:port (ICE-TCP beside UDP on one port number) are two candidates.
  function findLocalCandidate(ip, port, protocol) {
    for (let i = 0; i < context.localCandidates.length; i++) {
      const c = context.localCandidates[i];
      if (c.ip === ip && c.port === port &&
          (!protocol || (c.protocol || 'udp') === protocol)) return c;
    }
    return null;
  }

  // protocol: only a candidate of that transport ('udp' / 'tcp') — the same
  // ip:port over UDP and over TCP are two candidates.
  function findRemoteCandidate(ip, port, protocol) {
    for (let i = 0; i < context.remoteCandidates.length; i++) {
      const c = context.remoteCandidates[i];
      if (c.ip === ip && c.port === port &&
          (!protocol || (c.protocol || 'udp') === protocol)) return c;
    }
    return null;
  }

  function recomputePairPriorities() {
    // After role change, priorities must be recomputed and list re-sorted
    for (let i = 0; i < context.checkList.length; i++) {
      const p = context.checkList[i];
      p.priority = computePairPriority(context.controlling, p.local.priority, p.remote.priority);
    }
    // (BigInt priorities: compared, never subtracted — ice_candidate.js)
    context.checkList.sort((a, b) => (b.priority > a.priority) ? 1 : (b.priority < a.priority) ? -1 : 0);
    // A pair pruned under its old priority that now outranks the selected
    // one is worth checking again — pruning only ever drops dominated pairs.
    const sel = context.selectedPair;
    for (let i = 0; i < context.checkList.length; i++) {
      const p = context.checkList[i];
      if (!p.pruned || (sel && p.priority <= sel.priority)) continue;
      p.pruned = false;
      if (p.writeState === 'timeout' && !p.errorFailed) p.writeState = 'init';
    }
  }


  /* ========================= Pair formation ========================= */
  //
  // Pairs are formed whenever a new local OR remote candidate appears.
  // Dedup by (local key → remote key). Inserted sorted by priority.

  function formPairsForNewLocal(localCand) {
    for (let i = 0; i < context.remoteCandidates.length; i++) {
      tryMakePair(localCand, context.remoteCandidates[i]);
    }
  }

  function formPairsForNewRemote(remoteCand) {
    for (let i = 0; i < context.localCandidates.length; i++) {
      tryMakePair(context.localCandidates[i], remoteCand);
    }
  }


  /* ========================= mDNS candidates ========================= */
  // draft-ietf-mmusic-mdns-ice-candidates. All policy lives here and in
  // ice_mdns.js — the rest of the agent only ever sees resolved IPs.

  /** Lazily acquire the process-wide mDNS handle; dedup concurrent callers. */
  function withMdns(cb) {
    const m = context.mdns;
    if (m.handle) return cb(null, m.handle);
    if (m.acquiring) { m.acquiring.push(cb); return; }
    m.acquiring = [cb];
    iceMdns.acquire(m.options, function(err, handle) {
      const waiters = m.acquiring;
      m.acquiring = null;
      if (!err && !context.closed) m.handle = handle;
      else if (!err && context.closed) { try { handle.release(); } catch (_) {} }
      for (let i = 0; i < waiters.length; i++) waiters[i](err, m.handle);
    });
  }

  /**
   * Inbound ".local" candidate. Draft rules, in order:
   *   - iceTransportPolicy 'relay' → ignore (draft §3.2 step 2).
   *   - lite mode → ignore. A lite agent never initiates checks; it learns
   *     the peer's working address from the SOURCE of inbound checks
   *     (prflx), so resolving concealment names buys nothing by protocol —
   *     and lite deployments (cloud) can't reach the LAN's multicast anyway.
   *   - resolution disabled → drop + candidateerror (visible, not silent:
   *     the operator should know connectivity lost a path and why).
   *   - not a strict UUID label → drop + candidateerror (hostile peers
   *     must not aim our checks at "printer.local").
   *   - resolve via ice_mdns (single-IP rule enforced there); on success
   *     re-enter set_context with the real IP + mdnsName kept for logs.
   */
  function handleMdnsRemoteCandidate(cand) {
    if (context.phasePolicy === 'relay') return;
    if (context.mode === 'lite') return;

    if (!context.mdns.resolve) {
      ev.emit('candidateerror', {
        type: 'mdns', server: null, address: cand.ip,
        error: new Error(
          'Dropped ".local" remote candidate — mDNS resolution is not ' +
          'enabled on this agent (pass mdns: true, or inject an instance ' +
          'via mdns.instance).'),
      });
      return;
    }

    if (!isResolvableMdnsCandidate(cand.ip)) {
      ev.emit('candidateerror', {
        type: 'mdns', server: null, address: cand.ip,
        error: new Error(
          'Dropped ".local" remote candidate — not a single UUID label ' +
          '(draft-ietf-mmusic-mdns-ice-candidates §3.1/§3.2): ' + cand.ip),
      });
      return;
    }

    context.mdns.pendingResolves++;
    withMdns(function(err, handle) {
      if (err || context.closed) return finishMdnsResolve(cand, err);
      handle.resolve(cand.ip, function(err2, ip) {
        if (context.closed) return finishMdnsResolve(cand, err2 || null, null);
        finishMdnsResolve(cand, err2, ip);
      });
    });
  }

  function finishMdnsResolve(cand, err, ip) {
    context.mdns.pendingResolves--;

    if (context.closed) return;

    if (err || !ip) {
      if (err) {
        ev.emit('candidateerror', {
          type: 'mdns', server: null, address: cand.ip, error: err,
        });
      }
      // This resolution may have been the last thing keeping 'checking'
      // alive — re-evaluate terminal failure now that it's off the books.
      maybeFailAfterMdns();
      return;
    }

    const resolved = Object.assign({}, cand, {
      ip:       ip,
      mdnsName: cand.ip,   // original concealment name, for logs/stats
    });
    set_context({ add_remote_candidate: resolved });
  }

  /**
   * The last pending mDNS resolution ended: the connection state may now be
   * decided (computeFullState holds 'failed' while resolutions are in
   * flight — one can still create pairs).
   */
  function maybeFailAfterMdns() {
    if (context.mdns.pendingResolves > 0) return;
    if (context.mode === 'lite') return;
    set_context({ pair_tick: true });
  }

  /**
   * Signaling-boundary mask (outbound registration mode only).
   * Internal state always keeps real IPs — checks, prflx comparisons and
   * pair keys are untouched. Only the copy handed to the outside world is
   * concealed:
   *   - host candidates registered with mDNS: ip → UUID ".local" name
   *   - srflx/relay: raddr/rport scrubbed (0.0.0.0/:: + 9) — otherwise the
   *     related-address field would leak exactly the host IP the ".local"
   *     name exists to conceal. Matches Chrome's behavior and JSEP §5.2.1.
   */
  function maskCandidateForSignaling(c) {
    if (!c) return c;
    // iceTransportPolicy 'relay': a relay candidate's related address is the
    // host base it was allocated from — RFC 9429 §3.5.3: candidates the
    // policy forbids MUST NOT be exposed "indirectly ... via other fields,
    // such as the raddr/rport attributes". Scrubbed as for mDNS below.
    if (context.phasePolicy === 'relay' && c.relatedAddress &&
        c.relatedAddress !== '0.0.0.0' && c.relatedAddress !== '::') {
      const v6r = c.relatedAddress.indexOf(':') >= 0;
      return Object.assign({}, c, { relatedAddress: v6r ? '::' : '0.0.0.0', relatedPort: 9 });
    }
    if (!context.mdns.register) return c;
    if (c.mdnsName) {
      return Object.assign({}, c, { ip: c.mdnsName });
    }
    if ((c.type === 'srflx' || c.type === 'relay') && c.relatedAddress) {
      const v6 = c.relatedAddress.indexOf(':') >= 0;
      return Object.assign({}, c, {
        relatedAddress: v6 ? '::' : '0.0.0.0',
        relatedPort:    9,
      });
    }
    return c;
  }

  function tryMakePair(local, remote) {
    // Only candidates the current phase permits are paired (RFC 9429 §3.5.3,
    // W3C 4.2.5: "only these candidates will be used for connectivity
    // checks") — the kept ones of an earlier phase under another policy, and
    // relay candidates of a server no longer configured, are not.
    if (!localUsable(local)) return null;
    if (local.component !== remote.component) return null;
    if (local.protocol !== remote.protocol) return null;
    // Address family must match — RFC 8445 §6.1.2.2
    if (addressFamilyOf(local.ip) !== addressFamilyOf(remote.ip)) return null;
    if (findPair(local, remote)) return null;

    const pair = makePair(local, remote);
    insertPairSorted(pair);
    return pair;
  }

  function makePair(local, remote) {
    return {
      local:           local,
      remote:          remote,
      priority:        computePairPriority(context.controlling, local.priority, remote.priority),
      // waiting | in-progress | succeeded | failed (W3C pair state). Full
      // checks every pair as soon as it exists (libwebrtc has no frozen
      // stage); lite never checks — its pairs go straight to succeeded.
      state:           context.mode === 'lite' ? 'frozen' : 'waiting',
      valid:           false,

      // Nomination tracking
      nominated:       false,       // both sides agree — pair is the chosen one
      peerNominated:   false,       // remote sent USE-CANDIDATE on this pair
      weNominated:     false,       // our USE-CANDIDATE on it was answered

      // ── Full ICE check state (libwebrtc Connection) ──
      writeState:      'init',      // writable | unreliable | init | timeout
      receiving:       false,       // something arrived on it in the last 2.5s
      receivingChangedAt: 0,
      lastReceivedAt:  0,           // response, request, or (selected) data
      lastPingSent:    0,
      lastResponseAt:  0,
      pingsSent:       0,
      unanswered:      0,           // checks sent since the last response ...
      unansweredFirstAt: 0,         // ... the first of them
      unansweredFifthAt: 0,         // ... and the fifth (TooManyFailures)
      rttEstMs:        DEFAULT_RTT_MS,
      rttSamples:      0,
      pruned:          false,       // dominated by the selected pair: not checked any more
      errorFailed:     false,       // an unrecoverable STUN error: never checked again
      checkControlling: null,       // the role the last check claimed

      // ── Stats counters (W3C RTCIceCandidatePairStats) ───────────────────
      // Populated by sendPing/onPingResponse and by handleBindingRequest. Zero-valued until first activity.
      roundTripTime:      0,        // seconds, last measured (response - request)
      totalRoundTripTime: 0,        // seconds, sum of all measurements
      rttMeasurements:    0,        // count of successful response arrivals
      requestsSent:       0,        // connectivity checks we sent
      responsesReceived:  0,        // responses to our checks
      requestsReceived:   0,        // peer's connectivity checks we got
      responsesSent:      0,        // our responses to peer's checks
      consentRequestsSent: 0,       // checks on the working selected pair (keepalives)
      bytesSent:          0,        // STUN bytes sent on this pair
      bytesReceived:      0,        // STUN bytes received on this pair
      packetsSent:        0,        // STUN packets sent on this pair
      packetsReceived:    0,        // STUN packets received on this pair
      lastPacketSentTimestamp:     0,
      lastPacketReceivedTimestamp: 0,

      // Lite selection (cascade 2.5): when the peer's last authenticated
      // check arrived on this pair, and its last USE-CANDIDATE.
      requestReceivedAt:  0,
      nominatedAt:        0,
    };
  }

  function insertPairSorted(pair) {
    let lo = 0, hi = context.checkList.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (context.checkList[mid].priority < pair.priority) hi = mid;
      else lo = mid + 1;
    }
    context.checkList.splice(lo, 0, pair);
  }

  function findPair(local, remote) {
    for (let i = 0; i < context.checkList.length; i++) {
      const p = context.checkList[i];
      if (p.local.ip === local.ip && p.local.port === local.port &&
          p.remote.ip === remote.ip && p.remote.port === remote.port) {
        return p;
      }
    }
    return null;
  }


  /* ===================== Candidate policy (per phase) ===================== */
  //
  // RFC 9429 §3.5.3 / §4.1.18, W3C 4.4.1.6 "set a configuration": a new
  // iceTransportPolicy or ICE servers list takes effect at the next gathering
  // phase. The agent keeps its local candidates across restart() (their
  // sockets carry the previous pair's media, RFC 8445 §9), so the phase's
  // policy decides which of them it may announce and pair.

  // May this local candidate be announced and paired in the current phase?
  function localUsable(c) {
    if (!c || c.retired) return false;
    if (context.phasePolicy !== 'relay') return true;
    // 'relay': relay candidates, and peer-reflexive ones learned through a
    // relay (they share its TURN client) — never host / srflx.
    return c.type === 'relay' || !!c.turnClient;
  }

  // 'host:port' of each TURN server in the configured list.
  function configuredTurnKeys() {
    const keys = {};
    const list = context.iceServers || [];
    for (let i = 0; i < list.length; i++) {
      const urls = list[i].urls || list[i].url;
      const urlList = Array.isArray(urls) ? urls : [urls];
      for (let j = 0; j < urlList.length; j++) {
        const p = parseIceServerUri(urlList[j]);
        if (p && p.isTurn) keys[p.host + ':' + p.port] = true;
      }
    }
    return keys;
  }

  // Start of a gathering phase: latch the configured policy and retire the
  // relay candidates of TURN servers no longer configured.
  function beginPhase() {
    context._phasePending = false;
    context.phasePolicy = context.iceTransportPolicy;
    const turnKeys = configuredTurnKeys();
    const retiredClients = [];
    for (let i = 0; i < context.localCandidates.length; i++) {
      const c = context.localCandidates[i];
      if (c.turnKey && !turnKeys[c.turnKey]) { c.retired = true; retiredClients.push(c.turnClient); }
    }
    // (and the peer-reflexive candidates learned through those relays)
    for (let i = 0; i < context.localCandidates.length; i++) {
      const c = context.localCandidates[i];
      if (c.turnClient && retiredClients.indexOf(c.turnClient) >= 0) c.retired = true;
    }
    // Pairs formed before the phase began (remote candidates applied between
    // restart() and gather()) with candidates the phase forbids.
    context.checkList = context.checkList.filter(function(p) { return localUsable(p.local); });
    context.validList = context.validList.filter(function(p) { return localUsable(p.local); });
    releaseRetiredRelays(context.selectedPair);
  }

  // Close the TURN allocations of retired relay candidates that no pair in
  // use relies on (the previous pair keeps its own until a new one is
  // selected — cascade 2.5 calls this again then).
  function releaseRetiredRelays(inUse) {
    const keep = [];
    [inUse, context._previousPair, context.selectedPair].forEach(function(p) {
      if (p && p.local && p.local.turnClient) keep.push(p.local.turnClient);
    });
    const drop = {};
    for (let i = 0; i < context.localCandidates.length; i++) {
      const c = context.localCandidates[i];
      if (c.retired && c.turnKey && keep.indexOf(c.turnClient) < 0) drop[c.turnKey] = true;
    }
    const keys = Object.keys(drop);
    if (keys.length === 0) return;
    const closing = keys.map(function(k) { return context.turnClients[k]; });
    context.localCandidates = context.localCandidates.filter(function(c) {
      return !(c.turnKey && drop[c.turnKey]) && !(c.turnClient && closing.indexOf(c.turnClient) >= 0);
    });
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      const client = context.turnClients[k];
      delete context.turnClients[k];
      const pk = Object.keys(context.turnPermissions);
      for (let j = 0; j < pk.length; j++) {
        if (pk[j].indexOf(k + '|') !== 0) continue;
        const perm = context.turnPermissions[pk[j]];
        if (perm && perm.timer) clearTimeout(perm.timer);
        delete context.turnPermissions[pk[j]];
      }
      if (client) { try { client.close(); } catch (_) {} }
    }
  }


  /* ========================= Gathering ========================= */

  function startGathering() {
    if (context._gathering_host) return;
    context._gathering_host = true;

    if (context._phasePending) beginPhase();

    set_context({ gatheringState: 'gathering' });

    // Re-gather after ICE restart (RFC 8445 §9): existing candidates are
    // KEPT (their sockets carry the previous pair's media during the restart
    // window), but the SDP layer needs them announced again for the new
    // session. add_local_candidate's dedup would swallow them, so re-emit
    // here in trickle mode. Non-trickle mode already re-emits the full batch
    // at 'complete' (cascade 2.1) because restart() resets
    // _endOfCandidatesEmitted.
    if (context._reEmitOnGather) {
      context._reEmitOnGather = false;
      if (context.trickle) {
        const existing = context.localCandidates.filter(localUsable).sort(function(a, b) {
          return b.priority - a.priority;
        });
        for (let i = 0; i < existing.length; i++) ev.emit('candidate', maskCandidateForSignaling(existing[i]));
      }
    }

    // Classify iceServers
    const stunServers = [];
    const turnServers = [];
    for (let i = 0; i < context.iceServers.length; i++) {
      const srv = context.iceServers[i];
      const urls = srv.urls || srv.url;
      const urlList = Array.isArray(urls) ? urls : [urls];
      for (let j = 0; j < urlList.length; j++) {
        const p = parseIceServerUri(urlList[j]);
        if (!p) {
          // An unparseable URI used to be dropped without a word. An
          // application that configured five TURN servers and mistyped one
          // had no way to learn that its configuration had been discarded —
          // gathering simply proceeded with fewer servers than asked for.
          // Report it as a candidate error against the URI as written.
          ev.emit('candidateerror', {
            type:   'config',
            server: urlList[j],
            error:  new Error('Malformed ICE server URI — expected ' +
                              'stun:/stuns:/turn:/turns: followed by a host: ' +
                              String(urlList[j])),
          });
          continue;
        }
        if (p.isTurn) {
          turnServers.push({
            uri:        urlList[j],
            parsed:     p,
            username:   srv.username   || '',
            credential: srv.credential || '',
            // Pass-through TLS options for turns://
            servername:         srv.servername,
            rejectUnauthorized: srv.rejectUnauthorized,
            ca:                 srv.ca,
            // Pass-through DTLS (lemon-tls) + WebSocket transport options.
            // All optional: the Socket uses its own lemon-tls and quico's
            // WebSocket respectively when these are absent.
            connectDTLS:        srv.connectDTLS,
            lemonTls:           srv.lemonTls,
            alpnProtocols:      srv.alpnProtocols,
            minVersion:         srv.minVersion,
            maxVersion:         srv.maxVersion,
            mtu:                srv.mtu,
            WebSocket:          srv.WebSocket,
            wsPath:             srv.wsPath,
            wsUrl:              srv.wsUrl,
          });
        } else {
          stunServers.push({ uri: urlList[j], parsed: p });
        }
      }
    }

    // Relay-only policy skips srflx (but keeps relay)
    const relayOnly = (context.phasePolicy === 'relay');

    // ICE-Lite: only host candidates — no srflx/relay, no checks (RFC 8445 §6.1.1)
    const liteMode = (context.mode === 'lite');

    // Spawn host gathering (may bind several sockets, async)
    gatherHostCandidates(function() {
      context._gathering_host = false;

      if (!liteMode && !relayOnly) {
        // srflx gathering — one per STUN server × one per host base socket
        // (RFC 8445 §5.1.1.1 — gather srflx from each host).
        // Collect distinct bound sockets (includes loopback in test mode,
        // but loopback addrs won't have a public mapping; harmless attempts).
        const bases = collectGatheringBases();
        for (let i = 0; i < stunServers.length; i++) {
          for (let k = 0; k < bases.length; k++) {
            context._gathering_srflx++;
            gatherSrflxCandidate(stunServers[i], bases[k], function() {
              context._gathering_srflx--;
              checkGatheringComplete();
            });
          }
        }

        // Port-mapping gathering — one per host base, in parallel with
        // srflx/relay. Runs on the same collected bases; the gateway
        // discovery inside ice_portmap is shared process-wide, so only the
        // first agent in the process pays it.
        if (context.portmap.enabled) {
          for (let k = 0; k < bases.length; k++) {
            context._gathering_portmap++;
            gatherPortmapCandidate(bases[k], function() {
              context._gathering_portmap--;
              checkGatheringComplete();
            });
          }
        }
      }

      if (!liteMode) {
        // relay gathering — one per TURN server
        for (let i = 0; i < turnServers.length; i++) {
          context._gathering_relay++;
          gatherRelayCandidate(turnServers[i], function() {
            context._gathering_relay--;
            checkGatheringComplete();
          });
        }
      }

      // In case there are no srflx/relay servers, completion now
      checkGatheringComplete();
    });
  }

  function collectGatheringBases() {
    // Return distinct sockets bound to non-loopback base addresses.
    // Used for srflx fan-out: one Binding Request per base × STUN server.
    const bases = [];
    const seen = {};
    const skeys = Object.keys(context.sockets);
    for (let i = 0; i < skeys.length; i++) {
      const sock = context.sockets[skeys[i]];
      if (!sock) continue;
      let addr;
      try { addr = sock.address(); } catch (_) { continue; }
      if (!addr) continue;
      // Skip loopback — no public mapping discoverable
      if (addr.address === '127.0.0.1' || addr.address === '::1') continue;
      // Skip IPv4 link-local 169.254/16 — RFC 8445 recommends filtering
      if (addr.address.startsWith('169.254.')) continue;
      const key = addr.address + ':' + addr.port;
      if (seen[key]) continue;
      seen[key] = true;
      bases.push(sock);
    }
    return bases;
  }

  function checkGatheringComplete() {
    if (context.closed) return;
    if (context.gatheringState !== 'gathering') return;
    if (context._gathering_host) return;
    if (context._gathering_mdns_reg > 0) return;
    if (context._gathering_srflx > 0) return;
    if (context._gathering_relay > 0) return;
    if (context._gathering_portmap > 0) return;
    set_context({ gatheringState: 'complete' });
  }


  /* ── Port-mapping candidate gathering ── */
  //
  // For one host base: ask the gateway (via the shared ice_portmap handle)
  // to forward the base's own port, and advertise external ip:port as an
  // srflx candidate — same class as a STUN-derived mapping, because that is
  // exactly what it is: our address as seen/allocated on the NAT, with the
  // host base underneath. Distinct foundation ('portmap' in the server slot
  // of the RFC 8445 §5.1.1.3 tuple) keeps frozen-candidate logic from
  // treating it as the same path as a STUN srflx from the same base.
  //
  // done() is ALWAYS called exactly once — success, failure, or budget —
  // so gathering completion never wedges on a silent gateway (ice_portmap
  // enforces the budget internally with handle.cancel()).

  function gatherPortmapCandidate(baseSock, done) {
    let finished = false;
    function finish() { if (!finished) { finished = true; done(); } }

    let baseAddr;
    try { baseAddr = baseSock.address(); } catch (_) { return finish(); }
    const family = (baseAddr.family === 'IPv6' || baseAddr.address.indexOf(':') >= 0)
      ? 'IPv6' : 'IPv4';

    withPortmap(function(err, handle) {
      if (err || context.closed) {
        if (err) reportPortmapErrorOnce(err, baseAddr.address);
        return finish();
      }
      handle.mapPort(baseAddr.port, family, function(err2, mapping) {
        if (context.closed) return finish();
        if (err2) {
          // CGNAT / no-gateway kill the source: one clear candidateerror
          // for the first base, silence for the rest. Per-base budget
          // errors are reported per base — they can differ.
          if (err2.code === 'EPORTMAPCGNAT' || err2.code === 'EPORTMAPRELEASED') {
            reportPortmapErrorOnce(err2, baseAddr.address);
          } else {
            ev.emit('candidateerror', {
              type: 'portmap', server: null, base: baseAddr.address, error: err2,
            });
          }
          return finish();
        }

        context.portmap.mappedPorts.push({ port: baseAddr.port, family: family });

        const cand = {
          foundation:     computeFoundation('srflx', baseAddr.address, 'udp', 'portmap'),
          component:      COMPONENT_RTP,
          protocol:       'udp',
          priority:       computeCandidatePriority('srflx', LOCAL_PREFERENCE_DEFAULT, COMPONENT_RTP),
          ip:             mapping.externalIp,
          port:           mapping.externalPort,
          type:           'srflx',
          relatedAddress: baseAddr.address,
          relatedPort:    baseAddr.port,
          tcpType:        null,
          base:           { ip: baseAddr.address, port: baseAddr.port, family: family },
          via:            mapping.via,       // 'pcp' | 'natpmp' | 'upnp'
          // Transport hooks — traffic to the mapped port arrives on the
          // base socket itself; no separate transport.
          socket:         baseSock,
          turnClient:     null,
        };
        set_context({ add_local_candidate: cand });
        finish();
      });
    });
  }

  function withPortmap(cb) {
    const p = context.portmap;
    if (p.handle) return cb(null, p.handle);
    if (p.acquiring) { p.acquiring.push(cb); return; }
    p.acquiring = [cb];
    icePortmap.acquire(p.options, function(err, handle) {
      const waiters = p.acquiring;
      p.acquiring = null;
      if (!err && !context.closed) p.handle = handle;
      else if (!err && context.closed) { try { handle.release(); } catch (_) {} }
      for (let i = 0; i < waiters.length; i++) waiters[i](err, p.handle);
    });
  }

  function reportPortmapErrorOnce(err, baseIp) {
    if (context.portmap.errorOnce) return;
    context.portmap.errorOnce = true;
    ev.emit('candidateerror', {
      type: 'portmap', server: null, base: baseIp || null, error: err,
    });
  }


  /* ── Host candidate gathering ── */

  function gatherHostCandidates(done) {
    // If external socket(s) provided, use them as the only host candidates.
    // Supports IPv4 and/or IPv6 (dual-stack = both provided). This is the
    // shared-UDP-port server scenario — skip interface enumeration entirely.
    //
    // When context.announcedAddresses is set, the IPs/ports in those entries
    // override what socket.address() would report. This is essential for
    // cloud/NAT deployments where the bind IP (often 0.0.0.0) differs from
    // the public address the peer needs to reach. Each entry can be either a
    // string ('1.2.3.4') or an object ({ ip, port }). Family is inferred from
    // IP shape; port falls back to the socket's bound port when unspecified.
    if (context.externalSocket || context.externalSocket6) {
      const announced = context.announcedAddresses;

      if (announced && announced.length > 0) {
        for (let i = 0; i < announced.length; i++) {
          const a = announced[i];
          const ip = typeof a === 'string' ? a : a.ip;
          if (!ip) continue;
          const family = ip.indexOf(':') >= 0 ? 'IPv6' : 'IPv4';
          const sock = family === 'IPv6' ? context.externalSocket6 : context.externalSocket;
          if (!sock) continue;  // no socket for this family — skip
          let sockAddr;
          try { sockAddr = sock.address(); } catch (_) { continue; }
          const port = (typeof a === 'object' && a.port) ? a.port : sockAddr.port;
          addHostFromBoundSocket(sock, { address: ip, port: port, family: family });
        }
        // The same addresses over TCP, where a TCP carrier is given.
        for (let i = 0; i < announced.length; i++) {
          const a = announced[i];
          const ip = typeof a === 'string' ? a : a.ip;
          if (!ip) continue;
          const family = ip.indexOf(':') >= 0 ? 'IPv6' : 'IPv4';
          const tsock = family === 'IPv6' ? context.tcpSocket6 : context.tcpSocket;
          if (!tsock) continue;
          let tAddr;
          try { tAddr = tsock.address(); } catch (_) { continue; }
          const tport = (typeof a === 'object' && a.tcpPort) ? a.tcpPort : tAddr.port;
          addTcpPassiveHost(tsock, { address: ip, port: tport, family: family });
        }
      } else {
        // No announced addresses — use the bind addresses (legacy behavior).
        if (context.externalSocket) {
          const addr = context.externalSocket.address();
          addHostFromBoundSocket(context.externalSocket, {
            address: addr.address,
            port:    addr.port,
            family:  addr.family || 'IPv4',
          });
        }
        if (context.externalSocket6) {
          const addr = context.externalSocket6.address();
          addHostFromBoundSocket(context.externalSocket6, {
            address: addr.address,
            port:    addr.port,
            family:  addr.family || 'IPv6',
          });
        }
        [context.tcpSocket, context.tcpSocket6].forEach(function(tsock) {
          if (!tsock) return;
          let tAddr;
          try { tAddr = tsock.address(); } catch (_) { return; }
          addTcpPassiveHost(tsock, {
            address: tAddr.address,
            port:    tAddr.port,
            family:  tAddr.family || (tsock === context.tcpSocket6 ? 'IPv6' : 'IPv4'),
          });
        });
      }
      done();
      return;
    }

    const ifaces = os.networkInterfaces();
    const names = Object.keys(ifaces);

    // Re-gather (e.g. after ICE restart, or a repeated gather() call): skip
    // addresses we already hold a socket for. Re-binding would create a
    // duplicate host candidate on a new ephemeral port and leak the old
    // socket. Interfaces that appeared since the last gather (network
    // change — the main reason to restart ICE) still get fresh sockets.
    const alreadyBound = {};
    const boundKeys = Object.keys(context.sockets);
    for (let b = 0; b < boundKeys.length; b++) {
      const s = context.sockets[boundKeys[b]];
      try { alreadyBound[s.address().address] = true; } catch (_) {}
    }

    // A socket bound in an earlier phase under 'relay' (a TURN base) has no
    // host candidate; under 'all' it gets one now (a no-op where it has one).
    for (let b = 0; b < boundKeys.length; b++) {
      const s = context.sockets[boundKeys[b]];
      let ba;
      try { ba = s.address(); } catch (_) { continue; }
      if (ba) addHostFromBoundSocket(s, { address: ba.address, port: ba.port, family: ba.family });
    }

    const addrs = [];
    for (let i = 0; i < names.length; i++) {
      const list = ifaces[names[i]];
      for (let j = 0; j < list.length; j++) {
        const a = list[j];
        // Skip internal unless explicitly requested
        if (a.internal && !context.includeLoopback) continue;
        if (alreadyBound[a.address]) continue;
        if (a.family === 'IPv6') {
          if (!context.ipv6) continue;
          // Skip IPv6 link-local (RFC 8445 §5.1.1.1)
          if (a.address.toLowerCase().startsWith('fe80')) continue;
          // Skip IPv6 discard/documentation prefixes
          if (a.address.toLowerCase().startsWith('100::')) continue;
        } else if (a.family === 'IPv4') {
          // Skip IPv4 link-local 169.254/16 (RFC 3927, RFC 8445 recommends).
          // These are auto-configured addresses when DHCP fails — no peer
          // outside the local link segment can reach them.
          if (a.address.startsWith('169.254.')) continue;
        }
        addrs.push({ ip: a.address, family: a.family });
      }
    }

    if (addrs.length === 0) { done(); return; }

    let pending = addrs.length;
    for (let i = 0; i < addrs.length; i++) {
      bindUdpSocket(addrs[i].ip, addrs[i].family, function(sock, boundAddr) {
        if (sock && boundAddr) addHostFromBoundSocket(sock, boundAddr);
        pending--;
        if (pending === 0) done();
      });
    }
  }

  // A passive TCP host candidate (RFC 6544): "connect to me here". Its
  // socket is the TCP carrier, so checks answered and media sent on a pair
  // that uses it go back over the connection they came on. Not kept in
  // context.sockets — the carrier is the caller's, never closed here.
  //
  // Priority (RFC 6544 §4.2): local preference = 2^13 * direction-pref +
  // other-pref, passive = 4 → 40959, below a UDP host's 65535; a peer
  // that can reach UDP picks it.
  const TCP_PASSIVE_LOCAL_PREFERENCE = (4 << 13) + 8191;

  function addTcpPassiveHost(tsock, addr) {
    if (context.phasePolicy === 'relay') return;
    set_context({ add_local_candidate: {
      foundation:     computeFoundation('host', addr.address, 'tcp', ''),
      component:      COMPONENT_RTP,
      protocol:       'tcp',
      priority:       computeCandidatePriority('host', TCP_PASSIVE_LOCAL_PREFERENCE, COMPONENT_RTP),
      ip:             addr.address,
      port:           addr.port,
      type:           'host',
      relatedAddress: null,
      relatedPort:    null,
      tcpType:        'passive',
      base:           { ip: addr.address, port: addr.port, family: addr.family },
      socket:         tsock,
      turnClient:     null,
    } });
  }

  function addHostFromBoundSocket(sock, boundAddr) {
    const key = boundAddr.family + ':' + boundAddr.address + ':' + boundAddr.port;
    if (!context.sockets[key]) {
      context.sockets[key] = sock;
      if (!context.primarySocket) context.primarySocket = sock;
    } else if (findLocalCandidate(boundAddr.address, boundAddr.port, 'udp')) {
      return;   // known socket, its host candidate held
    }

    // Relay-only policy: bind the socket (needed as TURN allocate base) but
    // do NOT expose the host candidate externally. RFC 8445 §5.1.1.2 allows
    // filtering candidates; WebRTC's `iceTransportPolicy: 'relay'` mandates
    // that only relay candidates be gathered and used. (A socket kept from a
    // 'relay' phase gets its host candidate in the next 'all' phase.)
    if (context.phasePolicy === 'relay') return;

    const cand = {
      foundation:     computeFoundation('host', boundAddr.address, 'udp', ''),
      component:      COMPONENT_RTP,
      protocol:       'udp',
      priority:       computeCandidatePriority('host', LOCAL_PREFERENCE_DEFAULT, COMPONENT_RTP),
      ip:             boundAddr.address,
      port:           boundAddr.port,
      type:           'host',
      relatedAddress: null,
      relatedPort:    null,
      tcpType:        null,
      base:           { ip: boundAddr.address, port: boundAddr.port, family: boundAddr.family },
      // Transport hooks
      socket:         sock,
      turnClient:     null,
    };

    // Outbound concealment (mdns.register): register a UUID ".local" name
    // for this address BEFORE the candidate is added, so the very first
    // emission already carries the name (cand.mdnsName → masked at the
    // signaling boundary; internal ip stays real for checks). skipProbe
    // registration completes in ~0ms, but it is still async — the
    // _gathering_mdns_reg counter keeps gatheringState from reaching
    // 'complete' (and the null terminator from firing) underneath us.
    // Loopback / link-local are never registered: nothing to conceal.
    const concealable = context.mdns.register &&
      boundAddr.address !== '127.0.0.1' && boundAddr.address !== '::1' &&
      !boundAddr.address.startsWith('169.254.') &&
      !/^fe80:/i.test(boundAddr.address);

    if (!concealable) {
      set_context({ add_local_candidate: cand });
      return;
    }

    context._gathering_mdns_reg++;
    withMdns(function(err, handle) {
      function add(name) {
        if (name) {
          cand.mdnsName = name;
          context.mdns.registeredIps.push(cand.ip);
        }
        set_context({ add_local_candidate: cand });
        context._gathering_mdns_reg--;
        checkGatheringComplete();
      }
      if (err || context.closed) {
        // Registration is best-effort privacy: on failure, surface the
        // error and fall back to the plain candidate rather than losing
        // connectivity. (err → the operator asked for concealment and
        // should know it did not happen.)
        if (err) {
          ev.emit('candidateerror', {
            type: 'mdns', server: null, address: cand.ip, error: err,
          });
        }
        return add(null);
      }
      handle.register(cand.ip, function(err2, name) {
        if (err2) {
          ev.emit('candidateerror', {
            type: 'mdns', server: null, address: cand.ip, error: err2,
          });
          return add(null);
        }
        add(name);
      });
    });
  }

  function bindUdpSocket(ip, family, cb) {
    try {
      const type = family === 'IPv6' ? 'udp6' : 'udp4';
      const sock = dgram.createSocket(udpSocketOptions({ type, reuseAddr: true }, context.socketBufferSize));
      // A bind that fails (EADDRNOTAVAIL: an IPv6 address still tentative,
      // an address gone since networkInterfaces()) is an 'error' and no
      // bind callback: cb was never called, gatherHostCandidates' count
      // never reached 0 and gatheringState stayed 'gathering' — no
      // end-of-candidates (RFC 8838 §4). It ends this address's attempt.
      let bindSettled = false;

      sock.on('message', function(buf, rinfo) {
        // HOT PATH: Node dgram delivers Buffer (a Uint8Array subclass).
        // Skip new Uint8Array(buf) — it only allocates a view object.
        onSocketMessage(buf, rinfo, sock);
      });

      sock.on('error', function(err) {
        try {
          var _ea = sock.address();
          _diagLog('[ice-diag] ' + _diagTs() + ' SOCKET ERROR on ' +
                      _ea.address + ':' + _ea.port + ' — ' + (err && err.message));
        } catch (e) {
          _diagLog('[ice-diag] ' + _diagTs() + ' SOCKET ERROR (unbound) — ' + (err && err.message));
        }
        ev.emit('error', err);
        if (!bindSettled) {
          bindSettled = true;
          try { sock.close(); } catch (_) {}
          cb(null, null);
        }
      });

      sock.on('close', function() {
        // Bound identity is unreadable post-close; capture at bind below.
        _diagLog('[ice-diag] ' + _diagTs() + ' SOCKET CLOSED ' +
                    (sock.__diagBound || '(identity unknown)'));
      });

      sock.on('listening', function() {
        // success
      });

      sock.bind({ address: ip, port: 0, exclusive: false }, function() {
        if (bindSettled) return;
        bindSettled = true;
        let bound;
        try { bound = sock.address(); } catch (e) { cb(null, null); return; }
        sock.__diagBound = bound.address + ':' + bound.port;
        _diagLog('[ice-diag] ' + _diagTs() + ' SOCKET BOUND ' + sock.__diagBound);
        cb(sock, { address: bound.address, port: bound.port, family });
      });

      if (sock.unref) sock.unref();
    } catch (e) {
      cb(null, null);
    }
  }


  /* ── Server-reflexive (srflx) gathering ── */
  //
  // RFC 8445 §5.1.1.1: srflx candidates are gathered by sending STUN Binding
  // requests from EACH host base address. On a multi-homed machine (IPv4 +
  // IPv6, multiple NICs), each host candidate may have a different public
  // mapping, so we gather srflx per-base, not just from the primary socket.

  function gatherSrflxCandidate(server, sock, done) {
    if (!sock) { done(); return; }
    let baseAddr;
    try { baseAddr = sock.address(); } catch (_) { done(); return; }
    if (!baseAddr) { done(); return; }

    // Address family must match — don't send IPv4 STUN over IPv6 socket.
    const sockFamily = baseAddr.family || (baseAddr.address.indexOf(':') >= 0 ? 'IPv6' : 'IPv4');

    const encoded = wire.encode_message({
      method: wire.METHOD.BINDING,
      cls:    wire.CLASS.REQUEST,
      attributes: [],
      fingerprint: true,
    });
    const txHex = txIdHex(encoded.transactionId);

    // The gathering timeout. Declared before finish() reads it: finish can
    // run before the timer is armed — resolveHost answers a literal at once,
    // and an IPv4 STUN server on an IPv6 base (any dual-stack host) fails
    // there and then. With `const timer` below, that read was in the
    // temporal dead zone: a ReferenceError thrown out of gather() (or the
    // socket's bind callback), the remaining srflx / relay gathering never
    // started, and gatheringState stuck at 'gathering' — no end-of-candidates
    // (RFC 8838 §4: the agent signals it when gathering ends).
    let timer = null;
    let finished = false;
    function finish(err, info) {
      if (finished) return;
      finished = true;
      delete context.pendingTransactions[txHex];
      if (timer) { clearTimeout(timer); context._gather_timers.delete(timer); }
      if (context.closed) return;   // don't emit after close

      if (!err && info) {
        const cand = {
          foundation:     computeFoundation('srflx', baseAddr.address, 'udp', server.parsed.host + ':' + server.parsed.port),
          component:      COMPONENT_RTP,
          protocol:       'udp',
          priority:       computeCandidatePriority('srflx', LOCAL_PREFERENCE_DEFAULT, COMPONENT_RTP),
          ip:             info.ip,
          port:           info.port,
          type:           'srflx',
          relatedAddress: baseAddr.address,
          relatedPort:    baseAddr.port,
          tcpType:        null,
          base:           { ip: baseAddr.address, port: baseAddr.port, family: sockFamily },
          socket:         sock,
          turnClient:     null,
        };
        set_context({ add_local_candidate: cand });
      } else if (err) {
        ev.emit('candidateerror', {
          type: 'srflx', server: server.uri,
          base: baseAddr.address, port: baseAddr.port, error: err,
        });
      }
      done();
    }

    // Register transaction so onSocketMessage can route the response
    context.pendingTransactions[txHex] = {
      kind:    'gather-srflx',
      callback: function(msg) {
        const mapped = msg.getAttribute(wire.ATTR.XOR_MAPPED_ADDRESS)
                    || msg.getAttribute(wire.ATTR.MAPPED_ADDRESS);
        if (mapped) finish(null, { ip: mapped.ip || mapped.address, port: mapped.port });
        else finish(new Error('No mapped address in STUN response'));
      },
    };

    // DNS family preference: if the host base is IPv6, resolve server to IPv6.
    resolveHost(server.parsed.host, function(resolvedHost) {
      if (context.closed) { finish(new Error('agent closed')); return; }
      if (!resolvedHost) { finish(new Error('DNS resolve failed')); return; }
      // Skip if resolved address family doesn't match our socket family.
      const resolvedFamily = resolvedHost.indexOf(':') >= 0 ? 'IPv6' : 'IPv4';
      if (resolvedFamily !== sockFamily) {
        finish(new Error('STUN server family mismatch (' + resolvedFamily + ' ≠ ' + sockFamily + ')'));
        return;
      }
      try {
        // HOT PATH: encoded.buf is Uint8Array from wire.encode_message.
        // Create zero-copy Buffer view rather than copying ~20-100 bytes.
        const u = encoded.buf;
        const out = wire.to_buffer(u);
        sock.send(
          out,
          server.parsed.port || 3478,
          resolvedHost,
          function(err) { if (err) finish(err); }
        );
      } catch (e) {
        finish(e);
      }
    }, sockFamily);

    if (!finished) {
      timer = setTimeout(function() {
        finish(new Error('STUN timeout'));
      }, GATHER_SRFLX_TIMEOUT_MS);
      context._gather_timers.add(timer);
    }
  }


  /* ── Relay (TURN) candidate gathering ── */

  function gatherRelayCandidate(server, done) {
    if (!context.primarySocket) { done(); return; }

    // Re-gather (ICE restart): a live TURN client already exists for this
    // server — its relay candidate was re-announced by startGathering, and
    // allocating again would hold TWO allocations on the TURN server (and
    // orphan the old one, which the previous pair may still be relaying
    // media through). Reuse the existing allocation instead.
    const existingKey = server.parsed.host + ':' + server.parsed.port;
    if (context.turnClients[existingKey]) { done(); return; }

    const baseAddr = context.primarySocket.address();

    let finished = false;
    function finish(err, relayInfo, turnSocket) {
      if (finished) return;
      finished = true;
      if (timer) { clearTimeout(timer); context._gather_timers.delete(timer); }

      // LEAK FIX: on failure (allocate error, auth failure, timeout, agent
      // closed) the TURN client Socket — with its open transport and session
      // timers — was never closed and never stored anywhere teardown() could
      // reach. Every failed relay gather leaked a bound socket. Close it here;
      // on success it's stored in context.turnClients and teardown owns it.
      if ((err || context.closed) && _relaySocketRef) {
        try { _relaySocketRef.close(); } catch (_) {}
      }
      if (context.closed) return;   // don't emit after close

      if (!err && relayInfo && turnSocket) {
        const key = server.parsed.host + ':' + server.parsed.port;
        context.turnClients[key] = turnSocket;

        const cand = {
          foundation:     computeFoundation('relay', relayInfo.ip, 'udp', key),
          component:      COMPONENT_RTP,
          protocol:       'udp',
          priority:       computeCandidatePriority('relay', LOCAL_PREFERENCE_DEFAULT, COMPONENT_RTP),
          ip:             relayInfo.ip,
          port:           relayInfo.port,
          type:           'relay',
          relatedAddress: baseAddr.address,
          relatedPort:    baseAddr.port,
          tcpType:        null,
          base:           { ip: relayInfo.ip, port: relayInfo.port, family: addressFamilyOf(relayInfo.ip) },
          socket:         null,
          turnClient:     turnSocket,
          turnKey:        key,
        };
        set_context({ add_local_candidate: cand });
      } else if (err) {
        // Carry the local address and port, as the srflx path does. The
        // consumer maps base/port onto RTCPeerConnectionIceErrorEvent's
        // address/port, and W3C 4.8.2 ties those together: port 0 means no
        // address is available. Emitting neither left a spec-following
        // application unable to tell which local interface failed.
        ev.emit('candidateerror', {
          type: 'relay', server: server.uri,
          base: baseAddr.address, port: baseAddr.port, error: err,
        });
      }
      done();
    }

    // Use the Socket client from ./socket.js to allocate (lazy import).
    // _relaySocketRef mirrors turnSocket for finish()'s leak-fix close path
    // (finish is defined above this declaration, so it can't close over the
    // inner assignment directly in all engines' TDZ-safe way — keep one ref).
    let turnSocket;
    let _relaySocketRef = null;
    import('./socket.js').then(function(mod) {
      if (context.closed) { finish(new Error('agent closed')); return; }
      try {
        const Socket = mod.default || mod.Socket;
        const parsed = server.parsed;

        // Map ICE-URI transport → Socket.transportType. wire.parseUri already
        // resolves the scheme/?transport combo, so we mostly honour it directly
        // and only collapse "secure + stream" to TLS-over-TCP:
        //   turn:?transport=udp    → 'udp'
        //   turn:?transport=tcp    → 'tcp'
        //   turns:?transport=tcp   → 'tls'   (TLS over TCP)
        //   turns:?transport=udp   → 'dtls'  (DTLS, RFC 7350)
        //   turns: (no transport)  → 'tls'
        //   ws:// / wss://         → 'ws' / 'wss'
        let transportType;
        if (parsed.transport === 'ws' || parsed.transport === 'wss') {
          transportType = parsed.transport;
        } else if (parsed.transport === 'dtls') {
          transportType = 'dtls';
        } else if (parsed.secure) {
          transportType = 'tls';
        } else {
          transportType = parsed.transport || 'udp';
        }

        turnSocket = new Socket({
          isServer:      false,
          server:        parsed.host,
          port:          parsed.port || (parsed.secure ? 5349 : 3478),
          transportType: transportType,
          username:      server.username   || null,
          password:      server.credential || null,
          authMech:      (server.username && server.credential) ? 'long-term' : 'none',
          rto:           500,
          // TLS / WSS options (used when transportType is 'tls' or 'wss')
          servername:         server.servername         || parsed.host,
          rejectUnauthorized: server.rejectUnauthorized,  // undefined → default (true)
          ca:                 server.ca || null,
          // DTLS transport (lemon-tls) — injection optional; Socket uses its
          // own lemon-tls when these are absent.
          connectDTLS:        server.connectDTLS || null,
          lemonTls:           server.lemonTls    || null,
          alpnProtocols:      server.alpnProtocols || null,
          minVersion:         server.minVersion  || null,
          maxVersion:         server.maxVersion  || null,
          mtu:                server.mtu         || null,
          // WebSocket transport — injection optional; Socket uses quico's
          // WebSocket when absent.
          WebSocket:          server.WebSocket || null,
          wsPath:             server.wsPath    || null,
          wsUrl:              server.wsUrl     || null,
        });
        _relaySocketRef = turnSocket;
        attachTurnSocket(turnSocket);
      } catch (e) {
        finish(e);
      }
    }).catch(function(e) {
      finish(e);
    });

    function attachTurnSocket(turnSocket) {
      turnSocket.on('allocate:success', function(msg) {
        if (context.closed) { finish(new Error('agent closed')); return; }
        const relay = msg.getAttribute(wire.ATTR.XOR_RELAYED_ADDRESS);
        if (!relay) { finish(new Error('No XOR-RELAYED-ADDRESS')); return; }
        finish(null, { ip: relay.ip || relay.address, port: relay.port }, turnSocket);

        // Guard against double-wiring: if allocate:success fires more than
        // once (observed in some coturn scenarios), we must not stack extra
        // 'data' listeners — that causes duplicate packet delivery.
        if (turnSocket._iceDataWired) return;
        turnSocket._iceDataWired = true;

        // Wire TURN data incoming → packet handler.
        // socket.js emits `('data', peer, data, channel)` where peer is {ip,port}.
        turnSocket.on('data', function(peer, data /*, channel */) {
          if (context.closed) return;
          if (!data || !peer) return;
          // HOT PATH: data is already a Buffer. No need for new Uint8Array(data).
          onTurnRelayedData(data, peer.ip, peer.port, turnSocket);
        });
      });

      turnSocket.on('allocate:error', function(_msg, err) {
        finish(err || new Error('TURN allocate failed'));
      });

      turnSocket.on('error', function(err) {
        if (!finished) finish(err);
      });

      // Safety net: socket.js has a bug where TLS pre-handshake errors aren't
      // captured (the transport.on('error') listener is only attached after the
      // TLS handshake succeeds, inside bindTransport()). We poll briefly for the
      // transport being created, then attach our own error handler. Belt-and-
      // suspenders: also catches net/tcp errors that might slip through.
      let pollTries = 0;
      const pollTransport = setInterval(function() {
        if (finished || pollTries++ > 50) { clearInterval(pollTransport); return; }
        const tx = turnSocket && turnSocket.context && turnSocket.context.transport;
        if (tx && typeof tx.on === 'function' && !tx._iceAgentErrorHooked) {
          tx._iceAgentErrorHooked = true;
          tx.on('error', function(err) { if (!finished) finish(err); });
          clearInterval(pollTransport);
        }
      }, 10);
      if (pollTransport.unref) pollTransport.unref();

      turnSocket.connect(function() {
        if (context.closed) { finish(new Error('agent closed')); return; }
        try {
          turnSocket.allocate({ lifetime: 600 });
        } catch (e) { finish(e); }
      });
    }  // end attachTurnSocket

    const timer = setTimeout(function() {
      finish(new Error('TURN timeout'));
    }, GATHER_RELAY_TIMEOUT_MS);
    context._gather_timers.add(timer);
  }


  /* ========================= Ingress / Demux ========================= */
  //
  // Every UDP socket we bind routes incoming messages through here. The
  // STUN transactions (from gatherSrflxCandidate + connectivity checks) are
  // matched by transaction id; everything else (DTLS/RTP/RTCP) is forwarded
  // to the consumer via 'packet' event.

  function onSocketMessage(buf, rinfo, sock) {
    if (context.closed) return;

    const type = wire.demux(buf);
    if (type === 'stun') {
      handleStunMessage(buf, rinfo, sock);
    } else {
      // Full: data on the selected pair keeps it "receiving" (libwebrtc
      // counts any packet, not only checks).
      const sp = context.selectedPair;
      if (sp && context.mode !== 'lite' && sp.remote.port === rinfo.port && sp.remote.ip === rinfo.address) {
        sp.lastReceivedAt = Date.now();
      }
      // DTLS / RTP / RTCP / channel-data — forward
      ev.emit('packet', buf, rinfo, type);
    }
  }

  function onTurnRelayedData(buf, peerIp, peerPort, turnSocket) {
    if (context.closed) return;
    // A RELAYED PAYLOAD ARRIVES AS A Uint8Array, NOT A Buffer.
    //
    // The direct path emits what the UDP socket hands us, which is always a
    // Buffer. The relayed path arrives as a plain Uint8Array by the time it
    // reaches here, and a consumer calling readUInt16BE, readUInt32BE or any
    // other Buffer method on it throws.
    //
    // (The conversion point was not pinned down: the socket produces a Buffer
    // and wire's DATA decode is `d.slice(0)`, which preserves the type, so it
    // happens somewhere between. Normalising at this boundary fixes it
    // regardless, which is why it is here rather than at the origin.)
    //
    // Measured: every relayed RTP packet reached the SRTP layer and died on
    // `srtpPacket.readUInt16BE is not a function`, 121 of 121, with the
    // exception swallowed upstream — a call that connects, negotiates and
    // then carries no media, silently.
    //
    // Normalising here rather than at each consumer keeps the two paths
    // indistinguishable from the outside, which is what every listener on
    // 'packet' already assumes. Buffer.from over the same memory adds no copy.
    if (buf && !Buffer.isBuffer(buf) && typeof Buffer !== 'undefined') {
      buf = Buffer.from(buf.buffer || buf, buf.byteOffset || 0, buf.byteLength || buf.length);
    }
    const type = wire.demux(buf);
    // HOT PATH: RTP/RTCP/DTLS is 99% of traffic on an established call.
    // Avoid allocating rinfo object in that case — consumers rarely need
    // `family` for media packets; we synthesize it only for STUN.
    if (type === 'stun') {
      const rinfo = { address: peerIp, port: peerPort, family: addressFamilyOf(peerIp) };
      handleStunMessage(buf, rinfo, null, turnSocket);
    } else {
      const sp = context.selectedPair;
      if (sp && context.mode !== 'lite' && sp.remote.port === peerPort && sp.remote.ip === peerIp) {
        sp.lastReceivedAt = Date.now();
      }
      // Lightweight rinfo without family computation (not needed for media demux).
      ev.emit('packet', buf, { address: peerIp, port: peerPort }, type);
    }
  }

  // Short-term keys (RFC 8489 §9.1.1) for our password and the peer's,
  // computed once per password value rather than per STUN message. Keyed by
  // the value: the passwords change by assignment in several places
  // (set_context, restart()), and a changed value recomputes here.
  var _localKeyPwd = null, _localKey = null;
  var _remoteKeyPwd = null, _remoteKey = null;
  function localKey() {
    if (context.localPwd !== _localKeyPwd) {
      _localKeyPwd = context.localPwd;
      _localKey = _localKeyPwd ? wire.compute_short_term_key(_localKeyPwd) : null;
    }
    return _localKey;
  }
  function remoteKey() {
    if (context.remotePwd !== _remoteKeyPwd) {
      _remoteKeyPwd = context.remotePwd;
      _remoteKey = _remoteKeyPwd ? wire.compute_short_term_key(_remoteKeyPwd) : null;
    }
    return _remoteKey;
  }

  function handleStunMessage(buf, rinfo, sock, turnSocket) {
    // [ice-diag] FUNNEL ENTRY: every datagram classified as STUN logs its
    // arrival (rate-limited per source). Combined with the outcome logs
    // below, a disconnect investigation can now distinguish in one run:
    // never-arrived (no stun-rx) / arrived-but-unparseable (DECODE FAILED)
    // / parsed-but-dropped (validation 401s) / handled.
    if (_ICE_DBG && _diagRL('stunrx:' + rinfo.address + ':' + rinfo.port, 2000)) {
      var _lsock = '?';
      try { if (sock) { var _la = sock.address(); _lsock = _la.address + ':' + _la.port; } } catch (e) {}
      _diagLog('[ice-diag] ' + _diagTs() + ' stun-rx from ' +
                  rinfo.address + ':' + rinfo.port + ' → local ' + _lsock +
                  ' len=' + buf.length);
    }
    const msg = wire.decode_message(buf);
    if (!msg) {
      if (_ICE_DBG && _diagRL('stundecfail:' + rinfo.address + ':' + rinfo.port, 2000)) {
        _diagLog('[ice-diag] ' + _diagTs() + ' stun-rx DECODE FAILED from ' +
                    rinfo.address + ':' + rinfo.port + ' len=' + buf.length +
                    ' head=' + buf.slice(0, 8).toString('hex'));
      }
      return;
    }
    const txHex = txIdHex(msg.transactionId);

    // 1. Pending transaction (our outgoing STUN req — connectivity check, gather, etc.)
    const pending = context.pendingTransactions[txHex];
    if (pending) {
      if (_ICE_DBG && _diagRL('stunresp:' + rinfo.address + ':' + rinfo.port, 5000)) {
        _diagLog('[ice-diag] ' + _diagTs() + ' stun response consumed (kind=' +
                    pending.kind + ') from ' + rinfo.address + ':' + rinfo.port);
      }
      if (msg.cls === wire.CLASS.SUCCESS) {
        // For checks and consent: validate MESSAGE-INTEGRITY with remote password
        if ((pending.kind === 'check' || pending.kind === 'consent') && context.remotePwd) {
          if (!wire.verifyStunIntegrity(buf, msg, remoteKey())) return;   // silently drop bad-integrity response (RFC 8445 §7.2.5.1)
        }
        if (pending.callback) pending.callback(msg, rinfo);
        return;
      }
      if (msg.cls === wire.CLASS.ERROR) {
        // RFC 8489 §6.3.4 + RFC 8445 §7.2.5.1: 400 and some other errors MAY
        // NOT carry MESSAGE-INTEGRITY, but 401/438/487 MUST. For checks and
        // consent, validate integrity on errors that carry it — otherwise an
        // off-path attacker could spoof a 487 and force us to swap roles.
        const ec = msg.getAttribute(wire.ATTR.ERROR_CODE);
        const code = ec && ec.code;
        const requireMI = (pending.kind === 'check' || pending.kind === 'consent')
                       && context.remotePwd
                       && (code === 401 || code === 438 || code === 487);
        if (requireMI) {
          if (!wire.verifyStunIntegrity(buf, msg, remoteKey())) return;   // silently drop spoof attempts
        }
        if (pending.callback) pending.callback(msg, rinfo, new Error('STUN error response'));
        return;
      }
    }

    // 2. Incoming Binding Request — peer's connectivity check
    if (msg.method === wire.METHOD.BINDING && msg.cls === wire.CLASS.REQUEST) {
      handleBindingRequest(buf, msg, rinfo, sock, turnSocket);
      return;
    }

    // [ice-diag] Fallthrough — STUN we recognized but did not handle
    // (unknown transaction response, indication, non-binding method).
    if (_ICE_DBG && _diagRL('stunfall:' + rinfo.address + ':' + rinfo.port, 2000)) {
      _diagLog('[ice-diag] ' + _diagTs() + ' stun UNHANDLED from ' +
                  rinfo.address + ':' + rinfo.port +
                  ' method=' + msg.method + ' cls=' + msg.cls +
                  ' (pendingTx=' + (context.pendingTransactions[txHex] ? 'yes' : 'no') + ')');
    }
  }


  /* ========================= Part 2a: Connectivity Checks ========================= */

  /* ── Triggers ── */

  /* ── Imperative helpers called from set_context cascades ── */
  // These are side-effect functions. They do not set state directly — instead
  // they perform I/O or schedule timers, and when events occur they feed
  // results BACK through set_context.

  /* ── Full ICE: the check scheduler (libwebrtc's P2PTransportChannel) ──
   *
   * One timer drives everything for the life of the session: which pair to
   * check next, each pair's working state, the selected pair, pruning and
   * the connection state. It wakes every 48ms while nothing works well
   * (checking, or the selected pair not working/receiving) and every 250ms
   * otherwise; each wake-up sends at most one check. */

  function schedulePingTick(ms) {
    if (context.closed || context.mode === 'lite') return;
    if (context.pingTimer) clearTimeout(context.pingTimer);
    context.pingDueAt = Date.now() + ms;
    context.pingTimer = setTimeout(pingTick, ms);
    if (context.pingTimer.unref) context.pingTimer.unref();
  }

  // Something worth checking at once (a check arrived on a pair that does
  // not work yet, a new pair, a role switch): bring the next wake-up
  // forward — still paced at one check per 48ms.
  function requestPingSoon() {
    if (!context.pingTimer || context.closed) return;
    const t = Date.now();
    const due = Math.max(0, context.lastPingAt + PING_WEAK_MS - t);
    if (context.pingDueAt - t > due) schedulePingTick(due);
  }

  function isActive(p)    { return p.writeState !== 'timeout' && !p.errorFailed; }
  function readyToSend(p) { return p.writeState === 'writable' || p.writeState === 'unreliable'; }
  function isWeakPair(p)  { return !(p.writeState === 'writable' && p.receiving); }
  function channelWeak()  { const s = context.selectedPair; return !s || isWeakPair(s); }

  // libwebrtc Connection::UpdateState.
  function updatePairState(p, t) {
    if (p.lastReceivedAt) {
      const r = (t - p.lastReceivedAt) < RECEIVING_TIMEOUT_MS;
      if (r !== p.receiving) { p.receiving = r; p.receivingChangedAt = t; }
    }
    if (p.writeState === 'writable') {
      // TooManyFailures (5 checks, the 5th older than an RTT) AND
      // TooLongWithoutResponse (5s).
      if (p.unanswered >= UNWRITABLE_MIN_CHECKS &&
          t > p.unansweredFifthAt + p.rttEstMs &&
          t > p.unansweredFirstAt + UNWRITABLE_TIMEOUT_MS) {
        p.writeState = 'unreliable';
      }
    }
    if ((p.writeState === 'unreliable' || p.writeState === 'init') &&
        p.unanswered > 0 && t > p.unansweredFirstAt + INACTIVE_TIMEOUT_MS) {
      p.writeState = 'timeout';
      p.state = 'failed';
    }
  }

  // ── The comparator (libwebrtc BasicIceController) — > 0: a is better ──
  const WRITE_RANK = { writable: 0, unreliable: 1, init: 2, timeout: 3 };
  function compareStates(a, b, t) {
    const aw = a.writeState === 'writable', bw = b.writeState === 'writable';
    if (aw !== bw) return aw ? 1 : -1;
    const ra = WRITE_RANK[a.writeState], rb = WRITE_RANK[b.writeState];
    if (ra !== rb) return ra < rb ? 1 : -1;
    // Receiving counts only once it has held for a second on both — a
    // single late keepalive must not flip the selection back and forth.
    if (a.receiving !== b.receiving) {
      const th = t - RECEIVING_SWITCH_DELAY_MS;
      if (a.receivingChangedAt <= th && b.receivingChangedAt <= th) return a.receiving ? 1 : -1;
    }
    return 0;
  }
  function compareCandidates(a, b) {
    if (a.priority !== b.priority) return a.priority > b.priority ? 1 : -1;
    if (a.pruned !== b.pruned) return a.pruned ? -1 : 1;
    return 0;
  }
  function comparePairs(a, b, t) {
    const c = compareStates(a, b, t);
    if (c) return c;
    // Controlled side: what the peer nominated outranks what it did not.
    if (!context.controlling && a.peerNominated !== b.peerNominated) return a.peerNominated ? 1 : -1;
    return compareCandidates(a, b);
  }

  // The pair to select now, or null to keep the current one
  // (libwebrtc SortAndSwitchConnection / ShouldSwitchConnection).
  //
  // Both roles select among the pairs that work. Controlling: the choice is
  // ours; the peer learns it from USE-CANDIDATE. Controlled: as libwebrtc,
  // a working pair is selected before any nomination (media can start a
  // round trip sooner), and the comparator ranks what the peer nominated
  // above what it did not — so a nomination moves the selection to it.
  function fullSelect(t) {
    const sel = context.selectedPair;
    let top = null;
    for (let i = 0; i < context.checkList.length; i++) {
      const p = context.checkList[i];
      if (!readyToSend(p)) continue;
      if (!top) { top = p; continue; }
      const c = comparePairs(p, top, t);
      if (c > 0 || (c === 0 && p.rttEstMs < top.rttEstMs)) top = p;
    }
    if (!top || top === sel) return null;
    if (!sel) return top;
    const c = comparePairs(top, sel, t);
    if (c > 0) return top;
    if (c < 0) return null;
    return (top.rttEstMs <= sel.rttEstMs - MIN_RTT_IMPROVEMENT_MS) ? top : null;
  }

  // A pair's network: the local interface it leaves from.
  function networkOf(c) {
    return (c.base && c.base.ip) || c.relatedAddress || c.ip;
  }

  // Once the selected pair works and receives, stop checking the pairs it
  // dominates on the same network — equal or lower priority. Better pairs,
  // and pairs on other networks (backups), keep being checked
  // (libwebrtc PruneConnections; controlled side once nominated).
  function fullPrune() {
    const sel = context.selectedPair;
    if (!sel || isWeakPair(sel)) return;
    if (!context.controlling && !sel.nominated) return;
    const net = networkOf(sel.local);
    for (let i = 0; i < context.checkList.length; i++) {
      const p = context.checkList[i];
      if (p === sel || p.pruned) continue;
      if (networkOf(p.local) !== net) continue;
      if (compareCandidates(sel, p) < 0) continue;
      p.pruned = true;
      p.writeState = 'timeout';
    }
  }

  // The connection state from the pairs (libwebrtc ComputeIceTransportState):
  //   failed        — no pair alive any more (all timed out / failed)
  //   disconnected  — the selected pair stopped working, after it had worked
  //   checking      — pairs alive, none working yet
  //   connected     — the selected pair works
  // 'failed' stays until a restart (restart() resets it): the router drops
  // its fast-path routes on 'failed', and the SDP layer treats it as the
  // cue to restart — a quiet recovery would reach neither.
  function computeFullState(sel) {
    if (context.mode === 'lite' || context.closed) return null;
    if (context.state === 'failed' || context.state === 'closed') return null;
    const list = context.checkList;
    if (!context.remotePwd) return null;
    if (list.length === 0) return pairlessState();
    let anyActive = false;
    for (let i = 0; i < list.length; i++) if (isActive(list[i])) { anyActive = true; break; }
    if (!anyActive) return context.mdns.pendingResolves > 0 ? null : 'failed';
    // Restart in progress: the previous pair still carries media, and the
    // state does not leave 'connected' for the new checks (RFC 8445 §9.3.2).
    if (context._previousPair && !sel) return null;
    if (sel && sel.writeState === 'writable') { context.hasBeenWritable = true; return 'connected'; }
    if (context.hasBeenWritable) return 'disconnected';
    return 'checking';
  }

  // A session without a single pair (W3C 4.3.3 RTCIceTransportState
  // 'failed': gathering finished, end-of-candidates received, every pair
  // failed — none here — "and either zero local candidates were gathered or
  // the PAC timer has expired", RFC 8863 §4). Before, no pair meant no
  // verdict at all: a session whose candidates could never pair (a 'relay'
  // policy without a TURN server, the peer's address family only) stayed
  // 'new' / 'checking' forever.
  function pairlessState() {
    if (context.gatheringState !== 'complete' || !context.remoteCandidatesEnded) return null;
    if (context.mdns.pendingResolves > 0) return null;
    if (context.localCandidates.some(localUsable)) {
      const left = (context.pacStartedAt || Date.now()) + PAC_TIMEOUT_MS - Date.now();
      if (left > 0) {
        if (!context.pacTimer) {
          context.pacTimer = setTimeout(function() {
            context.pacTimer = null;
            if (!context.closed) set_context({ pair_tick: true });
          }, left);
          if (context.pacTimer.unref) context.pacTimer.unref();
        }
        return null;
      }
    }
    return 'failed';
  }

  function writableInterval(p, t) {
    if (p.pingsSent < MIN_PINGS_AT_WEAK) return PING_WEAK_MS;
    const missing = p.unanswered > 0 && (t - p.unansweredFirstAt) > 2 * p.rttEstMs;
    const stable = p.rttSamples > RTT_RATIO + 1 && !missing;
    return stable ? PING_STABLE_WRITABLE_MS : PING_UNSTABLE_WRITABLE_MS;
  }
  function pastWritableInterval(p, t) { return t >= p.lastPingSent + writableInterval(p, t); }

  function isPingable(p, weak, t) {
    if (p.errorFailed) return false;
    // While nothing works well, every pair — dead or pruned ones included —
    // is worth another try.
    if (weak) return true;
    if (p !== context.selectedPair && p.writeState === 'writable') {
      // A working backup: checked slowly.
      return p.rttSamples === 0 || t >= p.lastResponseAt + PING_BACKUP_MS;
    }
    return isActive(p);
  }

  // libwebrtc FindNextPingableConnection.
  function nextPingPair(t, weak) {
    const list = context.checkList;
    const sel = context.selectedPair;
    // 1. The selected pair's keepalive, when due.
    if (sel && sel.writeState === 'writable' && pastWritableInterval(sel, t)) return sel;
    // 2. Channel weak: the working pair checked longest ago.
    if (weak) {
      let w = null;
      for (let i = 0; i < list.length; i++) {
        const p = list[i];
        if (p === sel || p.writeState !== 'writable' || !pastWritableInterval(p, t)) continue;
        if (!w || p.lastPingSent < w.lastPingSent) w = p;
      }
      if (w) return w;
    }
    // 3. Triggered: a pair that does not work yet but the peer just checked.
    let trig = null;
    for (let i = 0; i < list.length; i++) {
      const p = list[i];
      if (p.writeState === 'writable' || !isPingable(p, weak, t)) continue;
      if (p.requestReceivedAt <= p.lastPingSent) continue;
      if (!trig || p.requestReceivedAt < trig.requestReceivedAt) trig = p;
    }
    if (trig) return trig;
    // 4. The rest: never-checked first, then checked longest ago; ties by
    //    priority (the list is sorted by priority).
    let best = null;
    for (let i = 0; i < list.length; i++) {
      const p = list[i];
      if (!isPingable(p, weak, t)) continue;
      if (p.writeState === 'writable' && !pastWritableInterval(p, t)) continue;
      if (!best || p.lastPingSent < best.lastPingSent) best = p;
    }
    return best;
  }

  function pingTick() {
    context.pingTimer = null;
    if (context.closed || context.mode === 'lite' || context.state === 'failed') return;
    const t = Date.now();
    const list = context.checkList;

    for (let i = 0; i < list.length; i++) updatePairState(list[i], t);

    // Forget check transactions nobody answered within 60s (once a second).
    if (t - context.lastTxSweepAt >= 1000) {
      context.lastTxSweepAt = t;
      const keys = Object.keys(context.pendingTransactions);
      for (let i = 0; i < keys.length; i++) {
        const e = context.pendingTransactions[keys[i]];
        if (e && e.kind === 'check' && t - e.sentAt > RESPONSE_TIMEOUT_MS) delete context.pendingTransactions[keys[i]];
      }
    }

    // Selection and state: through set_context, so the cascades (2.5 / 2.6)
    // and their events stay the one place that decides.
    set_context({ pair_tick: true });
    if (context.closed || context.state === 'failed') return;
    fullPrune();

    const weak = channelWeak();
    if (context.remoteUfrag && context.remotePwd) {
      const p = nextPingPair(t, weak);
      if (p) sendPing(p, t);
    }

    let interval = weak ? PING_WEAK_MS : PING_STRONG_MS;
    if (!weak) {
      for (let i = 0; i < list.length; i++) {
        if (isActive(list[i]) && list[i].pingsSent < MIN_PINGS_AT_WEAK) { interval = PING_WEAK_MS; break; }
      }
    }
    schedulePingTick(Math.min(interval, CHECK_RECEIVING_MS));
  }

  // USE-CANDIDATE (controlling), libwebrtc's default "semi-aggressive"
  // nomination: on every check of the selected pair and of any pair that
  // would beat it — so moving to a better pair later is just nominating it.
  // An ICE-lite peer follows our nomination alone: there, only on the
  // selected pair once it works.
  function useCandidateFor(pair) {
    const sel = context.selectedPair;
    if (context.remoteIceLite) return pair === sel && pair.writeState === 'writable';
    if (pair === sel) return true;
    return !sel || sel.writeState !== 'writable' || compareCandidates(sel, pair) < 0;
  }

  /* ── Outgoing connectivity check ── */

  function sendPing(pair, t) {
    if (context.closed) return;
    if (!context.remoteUfrag || !context.remotePwd) return;

    const sock = getSocketForLocalCandidate(pair.local);
    if (!sock && !pair.local.turnClient) {
      pair.errorFailed = true;
      pair.state = 'failed';
      pair.writeState = 'timeout';
      set_context({ pair_failed: pair });
      return;
    }

    // USERNAME is "<remote-ufrag>:<local-ufrag>" — RFC 8445 §7.2.2
    const username = context.remoteUfrag + ':' + context.localUfrag;

    // PRIORITY = what our local candidate's peer-reflexive priority WOULD be,
    // so the remote can add us as a prflx candidate if they discover a new
    // mapping. RFC 8445 §7.2.1.
    const prflxPriority = computeCandidatePriority('prflx', LOCAL_PREFERENCE_DEFAULT, pair.local.component);

    const attrs = [
      { type: wire.ATTR.USERNAME, value: username },
      { type: wire.ATTR.PRIORITY, value: prflxPriority },
    ];
    const controlling = context.controlling;
    if (controlling) {
      attrs.push({ type: wire.ATTR.ICE_CONTROLLING, value: context.tieBreaker });
    } else {
      attrs.push({ type: wire.ATTR.ICE_CONTROLLED, value: context.tieBreaker });
    }
    const useCandidate = controlling && useCandidateFor(pair);
    if (useCandidate) attrs.push({ type: wire.ATTR.USE_CANDIDATE, value: null });

    const encoded = wire.encode_message({
      method:      wire.METHOD.BINDING,
      cls:         wire.CLASS.REQUEST,
      attributes:  attrs,
      key:         remoteKey(),
      fingerprint: true,
    });

    const txHex = txIdHex(encoded.transactionId);
    const entry = {
      kind:         'check',
      pair:         pair,
      sentAt:       t,
      controlling:  controlling,   // the role this check claims (see handleRoleConflictFromResponse)
      useCandidate: useCandidate,
      callback: function(msg, rinfo, err) {
        delete context.pendingTransactions[txHex];
        onPingResponse(pair, entry, msg, rinfo, err);
      },
    };
    context.pendingTransactions[txHex] = entry;

    pair.checkControlling = controlling;
    if (pair === context.selectedPair && pair.writeState === 'writable') pair.consentRequestsSent++;
    pair.lastPingSent = t;
    pair.pingsSent++;
    if (pair.unanswered === 0) pair.unansweredFirstAt = t;
    pair.unanswered++;
    if (pair.unanswered === UNWRITABLE_MIN_CHECKS) pair.unansweredFifthAt = t;
    if (pair.state === 'frozen' || pair.state === 'waiting') pair.state = 'in-progress';
    context.lastPingAt = t;

    // Stats
    pair.requestsSent++;
    pair.bytesSent        += encoded.buf.length;
    pair.packetsSent++;
    pair.lastPacketSentTimestamp = t;

    sendStunToRemote(pair.local, pair.remote, encoded.buf);
  }

  // A response to one of our checks — on time or late (up to 60s).
  function markResponded(p, t, rttMs) {
    const wasWritable = p.writeState === 'writable';
    p.writeState     = 'writable';
    p.state          = 'succeeded';
    p.valid          = true;
    p.unanswered     = 0;
    p.lastResponseAt = t;
    p.lastReceivedAt = t;
    if (!p.receiving) { p.receiving = true; p.receivingChangedAt = t; }
    if (rttMs != null) {
      const r = Math.min(MAX_RTT_MS, Math.max(MIN_RTT_MS, rttMs));
      p.rttEstMs = p.rttSamples === 0 ? r : (RTT_RATIO * p.rttEstMs + r) / (RTT_RATIO + 1);
      p.rttSamples++;
    }
    return !wasWritable;
  }

  function onPingResponse(pair, entry, msg, rinfo, err) {
    if (context.closed) return;
    const t = Date.now();

    if (err) {
      // STUN error responses (libwebrtc Connection::OnConnectionRequestErrorResponse):
      //   487  role conflict — take the other role; the next check claims it.
      //   401 / 420 / 500 — recoverable (typically checks that raced the
      //        peer learning our credentials); the next check is the retry.
      //   anything else — the pair is dead for good.
      const ec = msg ? msg.getAttribute(wire.ATTR.ERROR_CODE) : null;
      const code = ec && ec.code;
      if (code === 487) { handleRoleConflictFromResponse(pair, entry.controlling); return; }
      if (!msg || code === 401 || code === 420 || code === 500) return;
      pair.errorFailed = true;
      pair.state = 'failed';
      pair.writeState = 'timeout';
      set_context({ pair_failed: pair });
      return;
    }

    // Stats: RTT and counters (RFC 7064 / RFC 8445 — response arrival minus
    // request send).
    const rttMs = t - entry.sentAt;
    pair.roundTripTime      = rttMs / 1000;           // seconds (spec format)
    pair.totalRoundTripTime += rttMs / 1000;
    pair.rttMeasurements++;
    pair.responsesReceived++;
    pair.packetsReceived++;
    pair.bytesReceived += (msg && msg.raw && msg.raw.length) ? msg.raw.length : 20;
    pair.lastPacketReceivedTimestamp = t;

    // Validate XOR-MAPPED-ADDRESS presence (RFC 8489)
    const mapped = msg.getAttribute(wire.ATTR.XOR_MAPPED_ADDRESS)
                || msg.getAttribute(wire.ATTR.MAPPED_ADDRESS);
    if (!mapped) {
      pair.errorFailed = true;
      pair.state = 'failed';
      pair.writeState = 'timeout';
      set_context({ pair_failed: pair });
      return;
    }
    const mappedIp   = mapped.ip || mapped.address;
    const mappedPort = mapped.port;

    // ─ RFC 8445 §7.2.5.3 — "Constructing the Valid Pair" ─
    // The valid pair is (the local candidate whose address EQUALS the mapped
    // address, pair.remote). A mapped address we do not know is a new
    // peer-reflexive local candidate: create it, and the pair over it. Both
    // pairs carry the same path (the same socket, the same remote), so both
    // are marked working.
    let validLocal = pair.local;
    if (mappedIp !== pair.local.ip || mappedPort !== pair.local.port) {
      validLocal = findLocalCandidate(mappedIp, mappedPort, pair.local.protocol || 'udp')
                || addPeerReflexiveLocal(mappedIp, mappedPort, pair.local);
    }
    let validPair = pair;
    if (validLocal !== pair.local) {
      validPair = findPair(validLocal, pair.remote) || tryMakePair(validLocal, pair.remote) || pair;
    }

    let changed = markResponded(pair, t, rttMs);
    if (validPair !== pair) changed = markResponded(validPair, t, rttMs) || changed;

    // Nomination: our USE-CANDIDATE answered (controlling), or the peer's
    // earlier USE-CANDIDATE on it (controlled) — RFC 8445 §7.2.5.3.4.
    if (entry.useCandidate && !validPair.weNominated) { validPair.weNominated = true; changed = true; }
    if (pair.peerNominated && !validPair.peerNominated) { validPair.peerNominated = true; changed = true; }
    if ((validPair.weNominated || validPair.peerNominated) && !validPair.nominated) {
      validPair.nominated = true;
      changed = true;
    }

    // Started working or newly nominated: decide now (cascades), rather than
    // at the next tick. A keepalive answered changes nothing to decide.
    if (changed) set_context({ pair_validated: validPair });
  }


  /* ── Lite: passive liveness ── */

  function initiateLiteLiveness() {
    // Triggered by cascade 2.8b: selectedPair set, lite, not already running.
    if (context.liteLivenessActive) return;
    context.liteLivenessActive = true;
    // Seed the clock at activation — the same reasoning consent uses:
    // never judge age against a zero from before the session existed.
    context.lastRequestReceivedAt = Date.now();
    scheduleNextLiteLivenessTick();
  }

  function scheduleNextLiteLivenessTick() {
    if (context.closed) return;
    // Wake at the next threshold when it comes before the regular tick, so
    // 'disconnected' / 'failed' land when they say, not up to a tick late.
    let ms = LITE_LIVENESS_TICK_MS;
    const age = Date.now() - context.lastRequestReceivedAt;
    const next = age < LITE_DISCONNECT_MS ? LITE_DISCONNECT_MS : (age < LITE_FAILED_MS ? LITE_FAILED_MS : Infinity);
    if (next !== Infinity && next - age > 0 && next - age < ms) ms = next - age;
    context.liteLivenessTimer = setTimeout(liteLivenessTick, ms);
    if (context.liteLivenessTimer.unref) context.liteLivenessTimer.unref();
  }

  function liteLivenessTick() {
    context.liteLivenessTimer = null;
    if (context.closed || !context.selectedPair) return;

    const age = Date.now() - context.lastRequestReceivedAt;

    if (_ICE_DBG) {
      _diagLog('[ice-diag] ' + _diagTs() + ' lite-liveness age=' + age + 'ms state=' + context.state);
    }

    if (age >= LITE_FAILED_MS) {
      // Terminal — and liteLivenessActive stays TRUE deliberately, the
      // exact latch lesson from consentTick: clearing it would let 2.8b
      // start a fresh cycle, reseed the clock, and erase the very
      // evidence that produced the failure. Cleared only by teardown and
      // ICE restart, the only paths that can produce a live peer again.
      set_context({ state: 'failed' });
      return;   // stop scheduling further
    }
    if (age >= LITE_DISCONNECT_MS) {
      if (context.state === 'connected') set_context({ state: 'disconnected' });
    } else if (context.state === 'disconnected') {
      set_context({ state: 'connected' });   // recovery: a request arrived
    }

    scheduleNextLiteLivenessTick();
  }

  function handleBindingRequest(buf, msg, rinfo, sock, turnSocket) {
    if (context.closed) return;

    // A check that arrived on a local candidate the current phase forbids
    // (a host socket under 'relay' — kept as the TURN base or from an 'all'
    // phase —, a retired relay) is dropped unanswered: answering is using
    // that candidate for connectivity checks, and the response's
    // XOR-MAPPED-ADDRESS / source would expose it (RFC 9429 §3.5.3).
    if (!incomingLocalUsable(sock, turnSocket)) {
      if (_ICE_DBG && _diagRL('drop-policy:' + rinfo.address + ':' + rinfo.port, 2000)) {
        _diagLog('[ice-diag] ' + _diagTs() + ' DROP binding-req from ' +
                    rinfo.address + ':' + rinfo.port + ' — arrived on a candidate the ' +
                    context.phasePolicy + ' policy forbids');
      }
      return;
    }

    // Verify USERNAME and MESSAGE-INTEGRITY with OUR password (RFC 8445 §7.3)
    // [ice-diag] Every drop branch below LOGS (rate-limited): a silent
    // validation failure looks identical to "packets stopped arriving"
    // from the outside, and that ambiguity cost a full debugging session
    // (bidi disconnect hunt, Aug 2026). Never again.
    if (!context.localPwd) {
      if (_ICE_DBG && _diagRL('drop-nopwd:' + rinfo.address + ':' + rinfo.port, 2000)) {
        _diagLog('[ice-diag] ' + _diagTs() + ' DROP binding-req from ' +
                    rinfo.address + ':' + rinfo.port + ' — context.localPwd is EMPTY');
      }
      return;
    }
    // A check without MESSAGE-INTEGRITY is unauthenticated: 400, never a
    // success (RFC 8445 §7.3, RFC 8489 §9.1.3). Accepting it would let anyone
    // who saw the ufrag nominate their own address as the selected pair.
    if (msg.integrity_offset === null) {
      if (_ICE_DBG && _diagRL('drop-nomi:' + rinfo.address + ':' + rinfo.port, 2000)) {
        _diagLog('[ice-diag] ' + _diagTs() + ' 400 binding-req from ' +
                    rinfo.address + ':' + rinfo.port + ' — no MESSAGE-INTEGRITY');
      }
      sendBindingError(msg, rinfo, sock, turnSocket, 400, 'Bad Request');
      return;
    }
    if (!wire.verifyStunIntegrity(buf, msg, localKey())) {
      if (_ICE_DBG && _diagRL('drop-integrity:' + rinfo.address + ':' + rinfo.port, 2000)) {
        _diagLog('[ice-diag] ' + _diagTs() + ' 401 binding-req from ' +
                    rinfo.address + ':' + rinfo.port + ' — MESSAGE-INTEGRITY failed ' +
                    '(their HMAC pwd != our context.localPwd — credential divergence?)');
      }
      sendBindingError(msg, rinfo, sock, turnSocket, 401, 'Unauthenticated');
      return;
    }

    // USERNAME must be "<our-ufrag>:<their-ufrag>"
    const usernameAttr = msg.getAttribute(wire.ATTR.USERNAME);
    if (typeof usernameAttr !== 'string' || usernameAttr.indexOf(':') < 0) {
      if (_ICE_DBG && _diagRL('drop-badusr:' + rinfo.address + ':' + rinfo.port, 2000)) {
        _diagLog('[ice-diag] ' + _diagTs() + ' 400 binding-req from ' +
                    rinfo.address + ':' + rinfo.port + ' — malformed USERNAME');
      }
      sendBindingError(msg, rinfo, sock, turnSocket, 400, 'Bad Request');
      return;
    }
    const colonIdx = usernameAttr.indexOf(':');
    const usernameLocal = usernameAttr.substring(0, colonIdx);
    if (usernameLocal !== context.localUfrag) {
      if (_ICE_DBG && _diagRL('drop-ufrag:' + rinfo.address + ':' + rinfo.port, 2000)) {
        _diagLog('[ice-diag] ' + _diagTs() + ' 401 binding-req from ' +
                    rinfo.address + ':' + rinfo.port + ' — USERNAME local part "' +
                    usernameLocal + '" != context.localUfrag "' + context.localUfrag + '"');
      }
      sendBindingError(msg, rinfo, sock, turnSocket, 401, 'Unauthenticated');
      return;
    }

    // Role conflict detection (RFC 8445 §7.3.1.1)
    const icControlling = msg.getAttribute(wire.ATTR.ICE_CONTROLLING);
    const icControlled  = msg.getAttribute(wire.ATTR.ICE_CONTROLLED);

    if (context.controlling && icControlling !== null) {
      // Both claim controlling
      if (compareTieBreakers(context.tieBreaker, icControlling.raw) >= 0) {
        // We win — tell them to switch (487)
        if (_ICE_DBG && _diagRL('roleconf:' + rinfo.address + ':' + rinfo.port, 2000)) {
          _diagLog('[ice-diag] ' + _diagTs() + ' 487 ROLE CONFLICT (both controlling, we win) → ' +
                      rinfo.address + ':' + rinfo.port + ' — our role=controlling');
        }
        sendBindingError(msg, rinfo, sock, turnSocket, 487, 'Role Conflict', localKey());
        return;
      }
      // We lose — switch to controlled
      _diagLog('[ice-diag] ' + _diagTs() + ' role conflict: both controlling, we LOSE → switching to controlled');
      switchRole(false);
    } else if (!context.controlling && icControlled !== null) {
      // Both claim controlled (RFC 8445 §7.3.1.1): the larger tie-breaker
      // takes the controlling role; the smaller answers 487 and keeps its
      // role. (This was the other way round: the larger answered 487, so
      // the smaller became controlling — against an RFC peer, which then
      // switched too, both ended controlling and a second conflict had to
      // settle it.)
      if (compareTieBreakers(context.tieBreaker, icControlled.raw) < 0) {
        if (_ICE_DBG && _diagRL('roleconf:' + rinfo.address + ':' + rinfo.port, 2000)) {
          _diagLog('[ice-diag] ' + _diagTs() + ' 487 ROLE CONFLICT (both controlled, theirs larger) → ' +
                      rinfo.address + ':' + rinfo.port + ' — our role=controlled');
        }
        sendBindingError(msg, rinfo, sock, turnSocket, 487, 'Role Conflict', localKey());
        return;
      }
      _diagLog('[ice-diag] ' + _diagTs() + ' role conflict: both controlled, ours larger → switching to controlling');
      switchRole(true);
    }

    // Find or create remote candidate (peer-reflexive if new)
    const inProtocol = rinfo.protocol === 'tcp' ? 'tcp' : 'udp';
    let remoteCand = findRemoteCandidate(rinfo.address, rinfo.port, inProtocol);
    if (!remoteCand) {
      const priorityAttr = msg.getAttribute(wire.ATTR.PRIORITY);
      const prflxPriority = priorityAttr || computeCandidatePriority('prflx', LOCAL_PREFERENCE_DEFAULT, COMPONENT_RTP);
      remoteCand = addPeerReflexiveRemote(rinfo.address, rinfo.port, prflxPriority, inProtocol);
    }

    // Find or create pair
    let pair = findPairByRemote(remoteCand, sock, turnSocket);
    if (!pair) {
      const local = findLocalForIncoming(sock, turnSocket);
      if (local) pair = tryMakePair(local, remoteCand);
    }

    // Stats: count this binding request on the pair (if we have one).
    if (pair) {
      pair.requestsReceived++;
      pair.packetsReceived++;
      pair.bytesReceived += buf.length;
      pair.lastPacketReceivedTimestamp = Date.now();
      pair.requestReceivedAt = pair.lastPacketReceivedTimestamp;
    }

    // Lite-liveness evidence: an authenticated request from the peer is
    // proof of life for the session (we are past MI validation here).
    // Deliberately not restricted to the selected pair — during pair
    // upgrades / restarts the peer is alive regardless of which pair its
    // check rode in on, and restricting produced false disconnects at
    // exactly the moments paths churn. Direct mutation, not set_context:
    // this is bookkeeping the TIMER reads (the 'Timer handles' rule),
    // not a flag that drives cascades.
    context.lastRequestReceivedAt = Date.now();

    // Always respond — even before processing, the peer needs a Success
    // [ice-diag] Log request+response per source (max 1/2s per source):
    // proves whether the peer's checks/consent keep arriving and that we
    // keep answering — and to WHICH address the answer goes.
    if (_ICE_DBG && _diagRL('bindreq:' + rinfo.address + ':' + rinfo.port, 2000)) {
      _diagLog('[ice-diag] ' + _diagTs() + ' binding-req from ' +
                  rinfo.address + ':' + rinfo.port +
                  ' → responding (pair=' + (pair ? 'known' : 'NONE') + ')');
    }
    sendBindingSuccess(msg, rinfo, sock, turnSocket);

    // Stats: we just sent a response.
    if (pair) {
      pair.responsesSent++;
      pair.packetsSent++;
      // Response size: STUN header (20) + XOR-MAPPED-ADDRESS (~12) + MI (~24) + FP (8)
      // Precise size is computed by sendBindingSuccess; approximate here.
      pair.bytesSent += 64;
      pair.lastPacketSentTimestamp = Date.now();
    }

    if (!pair) return;

    // RFC 8445 §8.2.1: USE-CANDIDATE marks this pair as nominated by peer.
    // Only meaningful when peer is controlling; we don't reject mis-sent
    // USE-CANDIDATE from controlled peers (RFC doesn't mandate rejection),
    // but in practice only the controlling peer should set it.
    const hasUseCandidate = (msg.getAttribute(wire.ATTR.USE_CANDIDATE) !== null);
    if (hasUseCandidate) { pair.peerNominated = true; pair.nominatedAt = Date.now(); }

    if (context.mode === 'lite') {
      // Lite: we never initiate checks. An inbound Binding Request from a
      // valid peer establishes the pair as usable (§6.1.1). But per §8.2.1,
      // we only SELECT after USE-CANDIDATE.
      pair.valid = true;
      pair.state = 'succeeded';
      if (pair.peerNominated) pair.nominated = true;
      set_context({ pair_validated: pair });
      return;
    }

    // Full. The peer's check is evidence the path works toward us: the pair
    // is receiving, and a pair that had timed out comes back to life
    // (unless pruned or failed for good — libwebrtc does the same).
    pair.lastReceivedAt = Date.now();
    if (pair.writeState === 'timeout' && !pair.pruned && !pair.errorFailed) {
      pair.writeState = 'init';
      pair.state = 'in-progress';
    }

    // If pair was previously valid (our outgoing check succeeded earlier)
    // and peer just nominated it via USE-CANDIDATE, mark nominated — cascade
    // will pick up auto-selection.
    if (pair.valid && pair.peerNominated && !pair.nominated) {
      pair.nominated = true;
      set_context({ pair_validated: pair });
      return;
    }

    // Triggered check (RFC 8445 §7.3.1.4): a pair that does not work yet but
    // the peer just checked goes first (nextPingPair step 3) — and soon.
    if (pair.writeState !== 'writable') requestPingSoon();
    // Kick cascades: a new (peer-reflexive) pair may start the scheduler.
    set_context({ pair_triggered: pair });
  }


  /* ── Outgoing Binding responses ── */

  function sendBindingSuccess(req, rinfo, sock, turnSocket) {
    const key = localKey();
    const encoded = wire.encode_message({
      method:        wire.METHOD.BINDING,
      cls:           wire.CLASS.SUCCESS,
      transactionId: req.transactionId,
      attributes: [
        // No explicit family — wire.detect_family() works off the IP string.
        // (ice_candidate's addressFamilyOf returns 'IPv4'/'IPv6' strings which
        // wire's encode_address strict-equals against numeric FAMILY.IPV4.)
        { type: wire.ATTR.XOR_MAPPED_ADDRESS, value: {
            ip:   rinfo.address,
            port: rinfo.port,
        } },
      ],
      key:         key,
      fingerprint: true,
    });
    sendStunRaw(sock, turnSocket, rinfo, encoded.buf);
  }

  // key: for an error to a request that WAS authenticated (487) — signed
  // with our password like a success (RFC 8489 §9.1.3), and the peer requires
  // it: an unsigned 487 is dropped as a possible spoof, so it never learns of
  // the conflict and keeps retransmitting the same check. 400 / 401 answer a
  // request that could not be authenticated, and go unsigned.
  function sendBindingError(req, rinfo, sock, turnSocket, code, reason, key) {
    const encoded = wire.encode_message({
      method:        wire.METHOD.BINDING,
      cls:           wire.CLASS.ERROR,
      transactionId: req.transactionId,
      attributes: [
        { type: wire.ATTR.ERROR_CODE, value: { code: code, reason: reason } },
      ],
      key:           key || undefined,
      fingerprint: true,
    });
    sendStunRaw(sock, turnSocket, rinfo, encoded.buf);
  }


  /* ── Role conflict handling ── */

  function handleRoleConflictFromResponse(pair, sentRole) {
    // 487: the role this check claimed conflicts — take the other one
    // (RFC 8445 §7.2.5.1: sent ICE-CONTROLLING → controlled, sent
    // ICE-CONTROLLED → controlling). By the role IN THE REQUEST, not a flip of
    // the current one: the role may have been switched since it was sent (a
    // request from the peer, §7.3.1.1), and a 487 to a retransmit of the old
    // check would then flip it back — into the very conflict it resolved.
    var sentControlling = (typeof sentRole === 'boolean') ? sentRole
                        : (typeof pair.checkControlling === 'boolean') ? pair.checkControlling : context.controlling;
    switchRole(!sentControlling);
    // The next check claims the new role — send it soon.
    requestPingSoon();
  }

  function switchRole(newControlling) {
    if (context.controlling === newControlling) return;
    context.controlling = newControlling;
    ev.emit('rolechange', newControlling ? 'controlling' : 'controlled');
    // Recompute pair priorities (RFC 8445 §6.1.2.3 — priority formula depends on role)
    for (let i = 0; i < context.checkList.length; i++) {
      const p = context.checkList[i];
      p.priority = computePairPriority(newControlling, p.local.priority, p.remote.priority);
    }
    // Re-sort check list
    context.checkList.sort((a, b) => (b.priority > a.priority) ? 1 : (b.priority < a.priority) ? -1 : 0);
  }

  // Lexicographic comparison of 8-byte tie-breakers.
  // Returns  1 if a>b, -1 if a<b, 0 if equal.
  function compareTieBreakers(a, b) {
    // `a` is our Uint8Array(8); `b` is raw Uint8Array(8) from remote's attribute
    if (!a || !b) return 0;
    for (let i = 0; i < 8; i++) {
      const av = a[i] || 0, bv = b[i] || 0;
      if (av > bv) return 1;
      if (av < bv) return -1;
    }
    return 0;
  }


  /* ── Peer-reflexive candidate helpers ── */

  function addPeerReflexiveLocal(ip, port, basedOn) {
    // Check if we already know this as a local candidate
    for (let i = 0; i < context.localCandidates.length; i++) {
      const c = context.localCandidates[i];
      if (c.ip === ip && c.port === port && c.component === basedOn.component) {
        return c;
      }
    }
    const cand = {
      foundation:     computeFoundation('prflx', basedOn.ip, basedOn.protocol || 'udp', ''),
      component:      basedOn.component,
      protocol:       basedOn.protocol || 'udp',
      priority:       computeCandidatePriority('prflx', LOCAL_PREFERENCE_DEFAULT, basedOn.component),
      ip:             ip,
      port:           port,
      type:           'prflx',
      relatedAddress: basedOn.ip,
      relatedPort:    basedOn.port,
      tcpType:        null,
      base:           basedOn.base || { ip: basedOn.ip, port: basedOn.port, family: addressFamilyOf(basedOn.ip) },
      socket:         basedOn.socket || null,
      turnClient:     basedOn.turnClient || null,
    };
    set_context({ add_local_candidate: cand });
    return cand;
  }

  function addPeerReflexiveRemote(ip, port, priority, protocol) {
    protocol = protocol || 'udp';
    // Check if already known
    for (let i = 0; i < context.remoteCandidates.length; i++) {
      const c = context.remoteCandidates[i];
      if (c.ip === ip && c.port === port && (c.protocol || 'udp') === protocol) return c;
    }
    const cand = {
      foundation:     'prflx:' + protocol + ':' + ip + ':' + port,   // unknown; synthesize unique
      component:      COMPONENT_RTP,
      protocol:       protocol,
      priority:       priority,
      ip:             ip,
      port:           port,
      type:           'prflx',
      relatedAddress: null,
      relatedPort:    null,
      tcpType:        protocol === 'tcp' ? 'active' : null,   // it connected to us
    };
    set_context({ add_remote_candidate: cand });
    return cand;
  }


  /* ── Candidate/pair lookups ── */

  function findPairByRemote(remoteCand, sock, turnSocket) {
    for (let i = 0; i < context.checkList.length; i++) {
      const p = context.checkList[i];
      if (p.remote !== remoteCand) continue;
      // Match local by socket/turnClient if we have context
      if (sock && p.local.socket === sock) return p;
      if (turnSocket && p.local.turnClient === turnSocket) return p;
      if (!sock && !turnSocket) return p;
    }
    return null;
  }

  function findLocalForIncoming(sock, turnSocket) {
    if (sock) {
      for (let i = 0; i < context.localCandidates.length; i++) {
        const c = context.localCandidates[i];
        if (c.socket === sock && localUsable(c)) return c;
      }
    }
    if (turnSocket) {
      for (let i = 0; i < context.localCandidates.length; i++) {
        const c = context.localCandidates[i];
        if (c.turnClient === turnSocket && localUsable(c)) return c;
      }
    }
    for (let i = 0; i < context.localCandidates.length; i++) {
      if (localUsable(context.localCandidates[i])) return context.localCandidates[i];
    }
    return null;
  }

  // Did a packet that came in on this socket / TURN client arrive on a
  // candidate the current phase permits? Arriving on a TURN client: that
  // relay must be usable. On a socket: under 'relay' never (no host
  // candidate may be used); otherwise unless every candidate on it is
  // forbidden (none: a socket without candidates yet — answered as before).
  function incomingLocalUsable(sock, turnSocket) {
    if (turnSocket) {
      for (let i = 0; i < context.localCandidates.length; i++) {
        const c = context.localCandidates[i];
        if (c.turnClient === turnSocket) return localUsable(c);
      }
      return true;
    }
    if (context.phasePolicy === 'relay') return false;
    let any = false;
    for (let i = 0; i < context.localCandidates.length; i++) {
      const c = context.localCandidates[i];
      if (c.socket !== sock || c.turnClient) continue;
      if (localUsable(c)) return true;
      any = true;
    }
    return !any;
  }


  /* ── Send STUN to a remote candidate (direct or via relay) ── */

  function sendStunToRemote(local, remote, buf) {
    try {
      if (local.turnClient) {
        // Relay candidate — needs Send indication (TURN) + permission to peer.
        // We lazily create the permission before sending STUN checks too,
        // otherwise coturn drops them.
        ensurePermission(local, remote, function(err) {
          if (err || context.closed) return;
          try {
            const ch = local.turnClient.getChannelByPeer(remote.ip, remote.port);
            if (ch) local.turnClient.sendChannel(ch, buf);
            else    local.turnClient.send({ ip: remote.ip, port: remote.port }, buf);
          } catch (_) {}
        });
        return;
      }
      const sock = getSocketForLocalCandidate(local);
      if (!sock) return;
      // HOT PATH: zero-copy Buffer view over Uint8Array from wire.encode_message.
      // Was Buffer.from(buf) which copies; Buffer.from(u.buffer, offset, len) is a view.
      const out = wire.to_buffer(buf);
      sock.send(out, remote.port, remote.ip, function() {});
    } catch (e) {
      // Swallow — STUN is fire-and-forget; next retransmit will retry.
    }
  }

  function sendStunRaw(sock, turnSocket, rinfo, buf) {
    try {
      if (turnSocket) {
        // Per RFC 8656 §10.2, Send indications to a peer require a Permission
        // for that peer's IP. Responding to an inbound check means we need
        // to pre-install that permission too.
        const local = findLocalForTurnClient(turnSocket);
        const doSend = () => {
          try { turnSocket.send({ ip: rinfo.address, port: rinfo.port }, buf); }
          catch (_) {}
        };
        if (local) {
          ensurePermission(local, { ip: rinfo.address, port: rinfo.port }, function(err) {
            if (err || context.closed) return;
            doSend();
          });
        } else {
          doSend();   // best-effort; may be silently dropped
        }
        return;
      }
      if (sock && typeof sock.send === 'function') {
        // HOT PATH: zero-copy Buffer view.
        const out = wire.to_buffer(buf);
        sock.send(out, rinfo.port, rinfo.address, function() {});
      }
    } catch (_) {}
  }

  function findLocalForTurnClient(turnSocket) {
    for (let i = 0; i < context.localCandidates.length; i++) {
      if (context.localCandidates[i].turnClient === turnSocket) {
        return context.localCandidates[i];
      }
    }
    return null;
  }


  /* ========================= Socket helpers ========================= */

  function getSocketForLocalCandidate(cand) {
    if (!cand) return context.primarySocket;
    if (cand.socket) return cand.socket;
    if (cand.turnClient) return cand.turnClient;
    const base = cand.base || cand;
    const key = (base.family || addressFamilyOf(base.ip)) + ':' + base.ip + ':' + base.port;
    return context.sockets[key] || context.primarySocket;
  }


  /* ========================= DNS (lazy) ========================= */

  function resolveHost(host, cb, preferFamily) {
    // Already numeric?
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return cb(host);
    if (host.indexOf(':') >= 0) return cb(host);   // IPv6 literal
    // Family: 0=any, 4=IPv4, 6=IPv6. Caller may prefer a specific family
    // to match the local socket family.
    let fam = 0;
    if (preferFamily === 'IPv4') fam = 4;
    else if (preferFamily === 'IPv6') fam = 6;
    else if (!context.ipv6) fam = 4;
    import('node:dns').then(function(dns) {
      dns.lookup(host, { family: fam }, function(err, address) {
        cb(err ? null : address);
      });
    }).catch(function() { cb(null); });
  }


  /* ========================= Teardown ========================= */

  function teardown() {
    // Stop all timers
    if (context.pacTimer)          { clearTimeout(context.pacTimer);          context.pacTimer = null; }
    if (context.pingTimer)         { clearTimeout(context.pingTimer);         context.pingTimer = null; }
    if (context.liteLivenessTimer) { clearTimeout(context.liteLivenessTimer); context.liteLivenessTimer = null; }
    context.liteLivenessActive = false;

    // mDNS: send goodbye for every name we registered, then drop our hold
    // on the shared instance (destroyed for real only when the last agent
    // in the process releases). In-flight resolutions self-cancel on the
    // closed flag.
    if (context.mdns.handle) {
      for (let i = 0; i < context.mdns.registeredIps.length; i++) {
        try { context.mdns.handle.unregister(context.mdns.registeredIps[i]); } catch (_) {}
      }
      context.mdns.registeredIps = [];
      try { context.mdns.handle.release(); } catch (_) {}
      context.mdns.handle = null;
    }

    // Port mappings: remove this agent's forwarding rules (the candidates
    // they served die with the agent), then drop the shared-mapper hold.
    // A crash skips this — which is why mappings carry a finite auto-renewed
    // lease and reclaim themselves.
    if (context.portmap.handle) {
      for (let i = 0; i < context.portmap.mappedPorts.length; i++) {
        const m = context.portmap.mappedPorts[i];
        try { context.portmap.handle.unmapPort(m.port, m.family); } catch (_) {}
      }
      context.portmap.mappedPorts = [];
      try { context.portmap.handle.release(); } catch (_) {}
      context.portmap.handle = null;
    }

    // Cancel outer gather timeouts (srflx / relay)
    if (context._gather_timers) {
      context._gather_timers.forEach(function(t) { clearTimeout(t); });
      context._gather_timers.clear();
    }

    // Cancel pending transactions
    const keys = Object.keys(context.pendingTransactions);
    for (let i = 0; i < keys.length; i++) {
      const t = context.pendingTransactions[keys[i]];
      if (t && t.timer) clearTimeout(t.timer);
    }
    context.pendingTransactions = {};

    // Close TURN permissions timers
    const permKeys = Object.keys(context.turnPermissions);
    for (let i = 0; i < permKeys.length; i++) {
      const perm = context.turnPermissions[permKeys[i]];
      if (perm && perm.timer) clearTimeout(perm.timer);
    }
    context.turnPermissions = {};

    // Close TURN clients we own
    const tkeys = Object.keys(context.turnClients);
    for (let i = 0; i < tkeys.length; i++) {
      try { context.turnClients[tkeys[i]].close(); } catch (e) {}
    }
    context.turnClients = {};

    // Close UDP sockets (but not external ones — they're owned by the caller)
    const skeys = Object.keys(context.sockets);
    for (let i = 0; i < skeys.length; i++) {
      const s = context.sockets[skeys[i]];
      if (s !== context.externalSocket && s !== context.externalSocket6) {
        try { s.close(); } catch (e) {}
      }
    }
    context.sockets = {};
    context.primarySocket = null;
  }


  /* ========================= External packet API ========================= */

  // Feed an incoming UDP packet from an externally-managed socket.
  // Called by the demuxer (e.g. WebRTCRouter) after the packet has been
  // identified as ICE/STUN traffic for this agent. rinfo must be in Node's
  // dgram format: { address, port, family, size }.
  function handleIncomingPacket(msg, rinfo) {
    if (context.closed) return;

    // Select the right socket based on the packet's source family, so that
    // STUN responses go back via the same family they arrived on — and, for
    // a packet from a TCP connection (rinfo.protocol 'tcp'), the TCP carrier,
    // so they go back over that connection.
    const isV6 = rinfo.family === 'IPv6';
    const sock = rinfo.protocol === 'tcp'
      ? (isV6 ? context.tcpSocket6 : context.tcpSocket)
      : (isV6 ? context.externalSocket6 : context.externalSocket);
    if (!sock) return;  // this family / transport not configured

    onSocketMessage(msg, rinfo, sock);
  }

  // Check whether the given 5-tuple matches this agent's active pair.
  // Used by WebRTCRouter for fast-path routing of subsequent packets:
  // when a packet's rinfo matches a validated pair, we can route without
  // parsing STUN USERNAME.
  function hasValidatedPair(rinfo) {
    if (context.closed) return false;
    const ip = rinfo.address;
    const port = rinfo.port;

    // Fast path — current selected pair
    const sp = context.selectedPair;
    if (sp && sp.remote.ip === ip && sp.remote.port === port) return true;

    // Previous pair during ICE restart (media still flows here)
    const pp = context._previousPair;
    if (pp && pp.remote.ip === ip && pp.remote.port === port) return true;

    // Any other validated pair (rare, but correct)
    for (let i = 0; i < context.validList.length; i++) {
      const p = context.validList[i];
      if (p.remote.ip === ip && p.remote.port === port) return true;
    }
    return false;
  }


  /* ========================= Public API ========================= */

  const api = {

    /** Raw context — advanced users may read any field directly. */
    context: context,

    /** Reactive core — external code may trigger cascades explicitly. */
    set_context: set_context,

    /** Event registration. */
    on:   function(name, fn) { ev.on(name, fn);   return this; },
    off:  function(name, fn) { ev.off(name, fn);  return this; },
    once: function(name, fn) { ev.once(name, fn); return this; },

    /** ICE parameters. Local auto-generated unless supplied in constructor. */
    get localParameters()  {
      return { ufrag: context.localUfrag, pwd: context.localPwd, iceLite: context.mode === 'lite' };
    },
    get remoteParameters() {
      return context.remoteUfrag
        ? { ufrag: context.remoteUfrag, pwd: context.remotePwd, iceLite: context.remoteIceLite }
        : null;
    },

    /**
     * Set the ICE role explicitly. Mirrors libwebrtc's per-negotiation
     * policy: the offerer of EACH O/A round is controlling, the answerer
     * controlled. RFC 8445 pins the role for the session, but Chrome
     * re-derives it every round — a full-ICE peer that stays RFC-pure
     * drifts out of sync after alternating renegotiations until both
     * sides claim 'controlled' and every consent check 487s (found live:
     * the M2 party-mode disconnect — sustained ROLE CONFLICT storm, all
     * connections, ~6s after a renegotiation). Interop beats purity:
     * follow the browser's policy. The tie-breaker path (§7.3.1.1)
     * remains as the safety net. Idempotent — set_context no-ops when
     * the role is unchanged.
     */
    setRole: function(controlling) {
      set_context({ controlling: !!controlling });
    },

    setLocalParameters: function(params) {
      if (!params) return;
      set_context({
        localUfrag: params.ufrag,
        localPwd:   params.pwd,
      });
    },

    setRemoteParameters: function(params) {
      if (!params) return;
      set_context({
        remoteUfrag:   params.ufrag,
        remotePwd:     params.pwd,
        remoteIceLite: !!params.iceLite,
      });
    },

    /** Change the configuration for the NEXT gathering phase (RFC 9429
     *  §4.1.18, W3C 4.4.1.6 "set a configuration"): nothing happens to the
     *  current one — its candidates, pairs and selected pair stay. The next
     *  phase begins at the first gather() after restart() (or the first
     *  gather() of all); it gathers and pairs under the new values:
     *
     *    iceTransportPolicy 'relay' — only relay candidates are announced
     *      (kept host / srflx ones are not re-announced) and paired, a check
     *      arriving on a host socket is dropped, relay candidates' raddr is
     *      scrubbed;
     *    iceTransportPolicy 'all'   — host candidates of the sockets kept
     *      from a 'relay' phase are announced, srflx gathered again;
     *    iceServers — STUN / TURN servers of the new list are used; the relay
     *      candidates of TURN servers no longer listed are not announced or
     *      paired, and their allocations are released once the previous
     *      pair (RFC 8445 §9) no longer uses them.
     *
     *  Members left out keep their value. An ICE restart is the caller's
     *  (JSEP's needs-ice-restart). Throws TypeError on an unknown policy. */
    setConfiguration: function(cfg) {
      if (!cfg || context.closed) return;
      if (cfg.iceTransportPolicy !== undefined) {
        if (cfg.iceTransportPolicy !== 'all' && cfg.iceTransportPolicy !== 'relay') {
          throw new TypeError('IceAgent.setConfiguration: invalid iceTransportPolicy "' +
            cfg.iceTransportPolicy + '" (expected "all" or "relay")');
        }
        context.iceTransportPolicy = cfg.iceTransportPolicy;
      }
      if (cfg.iceServers !== undefined) {
        context.iceServers = Array.isArray(cfg.iceServers) ? cfg.iceServers.slice() : [];
      }
    },

    /** The configured policy (next phase) and the current phase's. */
    get iceTransportPolicy() { return context.iceTransportPolicy; },
    get phasePolicy()        { return context.phasePolicy; },

    /** Add a remote candidate. Pass null to signal end-of-candidates. */
    addRemoteCandidate: function(candOrString) {
      if (candOrString === null || candOrString === undefined) {
        set_context({ add_remote_candidate: null });
        return;
      }
      const cand = (typeof candOrString === 'string')
        ? parseCandidate(candOrString)
        : candOrString;
      if (cand) {
        // Boundary hygiene for object-form candidates: the string parser
        // canonicalizes token case (protocol/type are case-insensitive
        // ABNF literals — RFC 8839 itself spells "UDP"), but callers that
        // hand us pre-parsed objects bypass it. Pair formation compares
        // these against our lowercase locals, so normalize here too.
        if (typeof cand.protocol === 'string') cand.protocol = cand.protocol.toLowerCase();
        if (typeof cand.type === 'string') cand.type = cand.type.toLowerCase();
        if (typeof cand.tcpType === 'string') cand.tcpType = cand.tcpType.toLowerCase();
        set_context({ add_remote_candidate: cand });
      }
    },

    /** Convenience: just the local candidates. */
    get localCandidates()  { return context.localCandidates.filter(localUsable).map(maskCandidateForSignaling); },
    get remoteCandidates() { return context.remoteCandidates.slice(); },
    get selectedPair()     { return context.selectedPair; },
    get state()            { return context.state; },
    get gatheringState()   { return context.gatheringState; },
    get role()             { return context.controlling ? 'controlling' : 'controlled'; },

    /** Trigger gathering. Idempotent — safe to call multiple times. */
    gather: function() {
      if (context.closed) return;
      startGathering();
    },

    /** Provide an external socket to share instead of binding our own.
     *  Infers IPv4 vs IPv6 from the socket's address and stores it in
     *  the appropriate context field. Prefer passing `socket`/`socket6`
     *  directly in the constructor — this method exists for backward
     *  compatibility and dynamic attachment after construction. */
    useSocket: function(sock) {
      if (!sock) return;
      try {
        const addr = sock.address();
        const family = addr.family ||
          (addr.address && addr.address.indexOf(':') >= 0 ? 'IPv6' : 'IPv4');
        if (family === 'IPv6') {
          set_context({ externalSocket6: sock });
        } else {
          set_context({ externalSocket: sock });
        }
        addHostFromBoundSocket(sock, {
          address: addr.address,
          port:    addr.port,
          family:  family,
        });
      } catch (e) {}
    },

    /** Feed an incoming UDP packet when running in external-socket mode.
     *  rinfo must be in Node's dgram format: { address, port, family, size }.
     *  See RFC 9443 for the demuxing scheme on shared UDP ports. */
    handlePacket: handleIncomingPacket,

    /** Returns true if the given 5-tuple matches this agent's selected
     *  pair, previous pair (during ICE restart), or any validated pair.
     *  Used by demuxers for fast-path routing. */
    hasValidatedPair: hasValidatedPair,

    /** Send application data through the selected pair. During an ICE
     *  restart, falls back to the previously-selected pair so that media
     *  continues to flow (RFC 8445 §9). Returns false if no pair is
     *  available (before the first nomination, or after close).  */
    send: function(buf) {
      const pair = context.selectedPair || context._previousPair;
      if (!pair) return false;
      // RFC 7675 §5.1: once consent has expired, stop sending application
      // data (our own checks still go out — they use sendViaPair directly,
      // and an answer to one restores the pair). Before, RTP, RTCP and DTLS
      // kept flowing at full rate after 'failed' to a peer that had stopped
      // answering. 'timeout' is the pair-level verdict (unanswered for
      // INACTIVE_TIMEOUT_MS); 'failed' the agent-level one, which in lite
      // mode is the passive liveness expiry.
      if (context.state === 'failed' || pair.writeState === 'timeout') return false;
      return sendViaPair(pair, buf);
    },

    /** ICE restart — RFC 8445 §9.
     *
     *  Generates new local ICE credentials and resets check state so that
     *  fresh connectivity checks can run with the new credentials.
     *
     *  CRITICAL: keeps the old selectedPair intact so that `agent.send()`
     *  continues to forward media over the previously-negotiated path
     *  (§9: "existing media streams MUST NOT be interrupted"). The cascade
     *  will replace it automatically when a new pair becomes nominated+valid.
     *
     *  Caller (WebRTC / SDP layer) responsibility after restart():
     *    1. Take the returned {ufrag, pwd} and put them in the new SDP
     *    2. Signal the new SDP to the peer
     *    3. Call setRemoteParameters() with the peer's new credentials
     *    4. Call gather() — this agent does NOT auto-gather on restart
     *    5. Feed peer's new candidates via addRemoteCandidate()
     *
     *  Events:
     *    'restart' (ufrag, pwd) — fired synchronously on entry
     *    'candidate' — re-gathered during new gather() pass
     *    'selectedpair' — when the new pair wins nomination (may replace old)
     *
     *  Returns: { ufrag, pwd } — the newly-generated local credentials, or
     *           null if the agent is closed.
     */
    restart: function() {
      if (context.closed) return null;

      const ufrag = randomUfrag();
      const pwd   = randomPwd();

      /* ── Cancel in-flight activity ──
       * Old pending transactions used the OLD credentials for MESSAGE-
       * INTEGRITY, and their callbacks reference pairs we're about to
       * remove. Clean them explicitly. */

      const txKeys = Object.keys(context.pendingTransactions);
      for (let i = 0; i < txKeys.length; i++) {
        const t = context.pendingTransactions[txKeys[i]];
        if (t && t.timer) clearTimeout(t.timer);
      }
      context.pendingTransactions = {};

      // Stop the check scheduler — the old session's checks would fail
      // MESSAGE-INTEGRITY against the new remotePwd (null until
      // setRemoteParameters). Cascade 2.2 starts it again for the new pairs.
      if (context.pingTimer)         { clearTimeout(context.pingTimer);         context.pingTimer = null; }
      if (context.liteLivenessTimer) { clearTimeout(context.liteLivenessTimer); context.liteLivenessTimer = null; }
      context.liteLivenessActive = false;
      context.lastRequestReceivedAt = 0;   // restart: new session, new clock (re-armed by 2.8b)
      // The PAC timer is the session's: the new one starts with the new remote credentials.
      if (context.pacTimer) { clearTimeout(context.pacTimer); context.pacTimer = null; }
      context.pacStartedAt = 0;

      /* ── Reset ICE check state ──
       * NOTE: sockets, turnClients, turnPermissions are intentionally
       * PRESERVED. The old selectedPair moves to _previousPair for send()
       * continuity while the new session is negotiated. */

      // Move selectedPair → _previousPair so send() can still forward media.
      // Cascade 2.5 will populate a new selectedPair once the new session
      // finds a nominated+valid pair, at which point _previousPair is dropped.
      context._previousPair = context.selectedPair;
      context.selectedPair  = null;

      context.checkList         = [];
      context.validList         = [];
      context.remoteCandidates  = [];
      context.remoteCandidatesEnded = false;
      context._endOfCandidatesEmitted = false;

      // Local candidates are PRESERVED (their sockets carry _previousPair's
      // media). The next gather() re-announces them to the SDP layer —
      // add_local_candidate's dedup would otherwise swallow them.
      context._reEmitOnGather = true;
      // ... under the policy configured now (beginPhase at the next gather()).
      context._phasePending = true;
      context.phasePolicy   = context.iceTransportPolicy;

      // Reset gather counters so checkGatheringComplete() works after re-gather
      context._gathering_host  = false;
      context._gathering_srflx = 0;
      context._gathering_relay = 0;

      /* ── New credentials via set_context (so cascades observe the change) ── */

      // Drop remote creds — caller MUST provide new ones via setRemoteParameters
      context.remoteUfrag   = null;
      context.remotePwd     = null;
      context.remoteIceLite = false;

      // Apply new local creds atomically via direct mutation — these feed
      // Binding Request USERNAME/MESSAGE-INTEGRITY for the new session.
      _diagLog('[ice-diag] ' + _diagTs() + ' RESTART: local creds rotated ' +
                  context.localUfrag + ' → ' + ufrag + ' (remote creds dropped, awaiting new)');
      context.localUfrag = ufrag;
      context.localPwd   = pwd;

      /* ── Feed cascades ──
       * We want gathering state to reset so consumers see a fresh gathering
       * pass. We DO NOT touch connection state — if we're currently
       * 'connected' via the old selectedPair, we stay 'connected'. If we're
       * in 'failed' state, restart is the conventional way out of failed —
       * pull us back to 'new' so consent/gathering flow restart correctly. */

      // Reset gathering state cascade (trickle events will re-emit)
      set_context({ gatheringState: 'new' });

      // If we were in failed/disconnected, drop back to 'new' so that
      // when checks start they transition to 'checking' properly. But if
      // we're 'connected' (old pair still works), LEAVE IT — the new
      // session will propagate to 'connected' naturally via maybeSelectPair.
      if (context.state === 'failed' || context.state === 'disconnected') {
        // No working path carried over: the new session starts from scratch
        // ('checking', not 'disconnected', while its pairs are checked).
        context.hasBeenWritable = false;
        set_context({ state: 'new' });
      }

      ev.emit('restart', { ufrag, pwd });
      return { ufrag, pwd };
    },

    /** The peer moved to a new transport under the same ICE credentials:
     *  start checking from scratch against that transport's candidates,
     *  keeping our credentials, local candidates and sockets.
     *
     *  For the SDP layer when WebRTC's BUNDLE tag changed: Chrome brings up
     *  a new ICE transport (new sockets) for the new tag, which knows only
     *  the candidates of the new tag's m-section, and closes the old one —
     *  once IT has applied the answer, so it can still answer for a while.
     *  Not an ICE restart (RFC 8445 §9): nothing is signalled.
     *
     *  Before this the selected pair kept pointing at the peer's old
     *  sockets: it looked working until consent ran out, the scheduler
     *  stayed at its slow connected pace and the new pairs waited 2.5-7s
     *  to be checked and selected, while the new DTLS handshake went to the
     *  closed port. Re-checking the existing pairs is not enough either:
     *  while the peer's old transport still answers (we answered its offer
     *  and it has not applied our answer yet), its pair works again at
     *  once, gets selected and nominated, and the pairs to the new
     *  transport are pruned as dominated — the handshake stuck on the old
     *  path for good.
     *
     *  remoteCandidates — the new transport's candidates (its m-section's,
     *  trickled ones included). The pairs and remote candidates of the old
     *  transport are dropped; its peer-reflexive ones come back from the
     *  peer's checks. Omitted: the current candidates are kept and their
     *  pairs re-checked (a peer that keeps its sockets).
     *
     *  Like a fresh transport: no selected pair (send() returns false until
     *  one is chosen), every pair unchecked — full ICE checks at the fast
     *  pace at once, triggered checks first; lite waits for the peer's next
     *  nomination — and the state 'checking'.
     *
     *  Events: 'statechange' ('checking', then 'connected'), and
     *  'selectedpair' when a pair is chosen. */
    recheck: function(remoteCandidates) {
      if (context.closed) return;

      // In-flight checks belong to the old pairs; their responses would
      // mark a pair working without a fresh round trip.
      const txKeys = Object.keys(context.pendingTransactions);
      for (let i = 0; i < txKeys.length; i++) {
        const t = context.pendingTransactions[txKeys[i]];
        if (!t || t.kind !== 'check') continue;
        if (t.timer) clearTimeout(t.timer);
        delete context.pendingTransactions[txKeys[i]];
      }

      const lite = context.mode === 'lite';
      const replace = Array.isArray(remoteCandidates);
      if (replace) {
        context.checkList        = [];
        context.remoteCandidates = [];
        context.remoteCandidatesEnded = false;
      } else {
        for (let i = 0; i < context.checkList.length; i++) {
          const p = context.checkList[i];
          p.state             = lite ? 'frozen' : 'waiting';
          p.valid             = false;
          p.nominated         = false;
          p.peerNominated     = false;
          p.weNominated       = false;
          p.writeState        = 'init';
          p.receiving         = false;
          p.receivingChangedAt = 0;
          p.lastReceivedAt    = 0;
          p.lastPingSent      = 0;
          p.lastResponseAt    = 0;
          p.pingsSent         = 0;
          p.unanswered        = 0;
          p.unansweredFirstAt = 0;
          p.unansweredFifthAt = 0;
          p.rttSamples        = 0;
          p.pruned            = false;
          p.errorFailed       = false;
          p.requestReceivedAt = 0;
          p.nominatedAt       = 0;
        }
      }
      context.validList       = [];
      context.selectedPair    = null;
      context._previousPair   = null;
      context.hasBeenWritable = false;
      // Lite liveness: stopped as restart() does, with a new clock. Its tick
      // returns without rescheduling while no pair is selected, and with
      // liteLivenessActive still set 2.8b would never start it again — the
      // new path would go unwatched. 2.8b starts it on the next selection.
      if (context.liteLivenessTimer) { clearTimeout(context.liteLivenessTimer); context.liteLivenessTimer = null; }
      context.liteLivenessActive = false;
      context.lastRequestReceivedAt = 0;

      _diagLog('[ice-diag] ' + _diagTs() + ' RECHECK: ' +
               (replace ? remoteCandidates.length + ' remote candidates of the new transport'
                        : context.checkList.length + ' pairs back to unchecked'));
      if (context.state !== 'new' && context.state !== 'checking') {
        set_context({ state: 'checking' });
      }
      if (replace) {
        for (let i = 0; i < remoteCandidates.length; i++) api.addRemoteCandidate(remoteCandidates[i]);
      }
      if (!lite && context.checkList.length > 0) schedulePingTick(0);
    },

    /** Close everything. Sockets, timers, transactions. Terminal.
     *  Flows through set_context cascade 2.9 which runs teardown() and
     *  transitions state='closed'. */
    close: function() {
      if (context.closed) return;
      set_context({ closed: true });
    },
  };

  // Send via a specific pair (direct UDP or TURN Send indication)
  /* HOT PATH — called on every RTP/RTCP/DTLS packet from the app.
   * Optimizations:
   *  - Avoid Buffer.from() when buf is already a Buffer (30fps video = 100s
   *    of MB/s of pointless copies otherwise).
   *  - Permission lookup is O(1) on an object; if fresh, skip the callback
   *    and refresh-scheduling entirely by using a cached flag on the pair.
   *  - Cache the socket on the pair after first send so we don't traverse
   *    the context.sockets map on every packet.
   */
  function sendViaPair(pair, buf) {
    const local = pair.local;
    const remote = pair.remote;

    // TURN relay path
    if (local.type === 'relay' && local.turnClient) {
      // Fast path: permission already confirmed on this pair
      if (pair._permissionReady) {
        try {
          const ch = pair._channel
                  || local.turnClient.getChannelByPeer(remote.ip, remote.port);
          if (ch) {
            if (!pair._channel) pair._channel = ch;
            local.turnClient.sendChannel(ch, buf);
          } else {
            local.turnClient.send({ ip: remote.ip, port: remote.port }, buf);
          }
        } catch (e) {}
        return true;
      }

      // First send (or permission expired): ensure permission, then mark ready
      ensurePermission(local, remote, function(err) {
        if (err) return;
        pair._permissionReady = true;
        try {
          const ch = local.turnClient.getChannelByPeer(remote.ip, remote.port);
          if (ch) { pair._channel = ch; local.turnClient.sendChannel(ch, buf); }
          else    { local.turnClient.send({ ip: remote.ip, port: remote.port }, buf); }
        } catch (e) {}
      });
      return true;
    }

    // Direct UDP path — cache socket on pair for O(1) subsequent sends
    let sock = pair._sock;
    if (!sock) {
      sock = getSocketForLocalCandidate(local);
      if (!sock || !sock.send) return false;
      pair._sock = sock;
    }
    try {
      // HOT PATH: RTP/RTCP media packets flow through here at 30-50 fps.
      // Buffer.from(u.buffer, offset, len) is a zero-copy view, unlike
      // Buffer.from(u) which would copy ~1200 bytes per packet.
      const out = wire.to_buffer(buf);
      sock.send(out, remote.port, remote.ip);
      return true;
    } catch (e) {
      return false;
    }
  }

  // TURN permission management (used both for checks and media)
  function ensurePermission(localRelay, remoteCand, cb) {
    const turnKey = localRelay.turnKey;
    const permKey = turnKey + '|' + remoteCand.ip;
    const existing = context.turnPermissions[permKey];
    const now = Date.now();

    if (existing && existing.expires > now + 5000) {
      return cb && cb(null);
    }

    const client = localRelay.turnClient;
    if (!client) return cb && cb(new Error('No TURN client'));

    client.createPermission([{ ip: remoteCand.ip, port: remoteCand.port }], function(err) {
      if (err) {
        if (cb) cb(err);
        return;
      }
      // Schedule refresh before expiry
      const existing2 = context.turnPermissions[permKey];
      if (existing2 && existing2.timer) clearTimeout(existing2.timer);

      const timer = setTimeout(function() {
        if (context.closed) return;
        ensurePermission(localRelay, remoteCand, null);
      }, TURN_PERMISSION_REFRESH_MS);
      if (timer.unref) timer.unref();

      context.turnPermissions[permKey] = {
        expires: now + TURN_PERMISSION_LIFETIME_MS,
        timer:   timer,
      };
      if (cb) cb(null);
    });
  }

  // Copy api → this
  for (const k of Object.keys(api)) {
    const desc = Object.getOwnPropertyDescriptor(api, k);
    Object.defineProperty(this, k, desc);
  }

  return this;
}


/* ========================= Exports ========================= */

export { IceAgent };
export default IceAgent;