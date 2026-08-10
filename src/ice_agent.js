// src/ice_agent.js
// ICE Agent (RFC 8445) — interactive connectivity establishment.
// Supports: full ICE + ICE-Lite, vanilla + trickle gathering, regular nomination,
// consent freshness (RFC 7675), ICE restart, TURN permissions for relay,
// IPv4 + IPv6, peer-reflexive candidates, role conflict resolution.
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

import crypto from 'node:crypto';
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
import * as icePortmap from './ice_portmap.js';


/* ========================= Constants ========================= */

// ICE states — RFC 8445 §6.1.4 (connection state)
// new, checking, connected, completed, disconnected, failed, closed
const ICE_STATES = ['new', 'checking', 'connected', 'completed', 'disconnected', 'failed', 'closed'];
const GATHERING_STATES = ['new', 'gathering', 'complete'];

// (Type preferences live in ice-candidate.js.)

// STUN retransmission — RFC 5389 §7.2.1
const STUN_INITIAL_RTO_UDP = 500;     // ms
const STUN_MAX_RETRANSMISSIONS = 7;   // → total ≈ 39.5s
const STUN_RC = STUN_MAX_RETRANSMISSIONS;
const STUN_RM = 16;                   // final timeout multiplier

// Connectivity check pacing — RFC 8445 §6.1.4.2
const CHECK_PACE_MS = 50;

// Nomination — RFC 8445 §8.1.2. Wait this long after first valid pair to let
// other pairs complete, so we can nominate the actual best (not just first).
const NOMINATION_DELAY_MS = 100;

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

// Consent Freshness — RFC 7675.
// After ICE completes, we verify the path is still alive by sending a STUN
// Binding Request every ~15s. If no success response for 30s, declare the
// session "disconnected". After 45s of no success, declare "failed".
// Values are env-overridable for tests (so we don't wait 45s in unit tests).
const CONSENT_INTERVAL_MS       = parseInt(process.env.ICE_CONSENT_INTERVAL_MS   || '15000', 10);
const CONSENT_RANDOMIZATION     = 0.2;     // ±20% per RFC 7675 §5.1
const CONSENT_DISCONNECT_MS     = parseInt(process.env.ICE_CONSENT_DISCONNECT_MS || '30000', 10);
const CONSENT_FAILED_MS         = parseInt(process.env.ICE_CONSENT_FAILED_MS     || '45000', 10);

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
  return crypto.randomBytes(3).toString('base64').replace(/=/g, '');
}

function randomPwd() {
  // RFC 8445 §16.1: password ≥ 128 bits of randomness = ≥ 22 ice-chars
  // 16 random bytes → 24 base64 chars (2 '=' padding); after stripping = 22 chars.
  // NOTE: ice-char includes '+' and '/', so we do NOT strip those.
  return crypto.randomBytes(16).toString('base64').replace(/=/g, '');
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
    iceTransportPolicy:   options.iceTransportPolicy || 'all',   // 'all' | 'relay'
    includeLoopback:      !!options.includeLoopback,
    ipv6:                 options.ipv6 !== false,                // default true
    portRange:            options.portRange || [0, 0],           // [min, max]; 0 = any
    components:           options.components || 1,
    tieBreaker:           crypto.randomBytes(8),

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
    triggeredQueue:       [],

    // ── Selected pair ──
    selectedPair:         null,

    // ── Sockets ──
    sockets:              {},    // key 'family:ip:port' → dgram.Socket
    primarySocket:        null,  // preferred socket for sending (set by selection)
    externalSocket:       options.socket  || null,  // externally-provided IPv4 socket
    externalSocket6:      options.socket6 || null,  // externally-provided IPv6 socket

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

    // ── Timers (bookkeeping — handles, not "state" that triggers cascades) ──
    checkTimer:           null,
    nominationTimer:      null,
    consentTimer:         null,
    consentActive:        false,  // consent freshness cycle is running (see 2.8)

    // ── State tracked by set_context cascades ──
    selectedPair:         null,   // when set → cascade: emit, state=connected, stop checks, start consent
    nominationStarted:    false,  // when true → nomination timer is scheduled
    consentLastSuccessAt: 0,      // updated when a consent reply arrives

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
    _reEmitOnGather:      false,   // set by restart(): re-announce kept candidates
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
  // Timer handles (checkTimer, nominationTimer, consentTimer) are bookkeeping,
  // mutated imperatively alongside the state flag that DOES cascade. E.g.:
  //   - nominationStarted=true (flag)   +   nominationTimer=<handle> (bookkeeping)
  //   - selectedPair=<pair>    (flag)   +   consentTimer=<handle>    (bookkeeping)

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
          console.log('[ice-diag] ' + _diagTs() + ' ROLE SET via opts: ' +
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
        console.log('[ice-diag] ' + _diagTs() + ' localUfrag set via opts: ' +
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
          console.log('[ice-diag] ' + _diagTs() + ' ICE STATE ' + prev + ' → ' + context.state);
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
      if (cand && !findLocalCandidate(cand.ip, cand.port)) {
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
        formPairsForNewRemote(cand);
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


    /* Nomination flag */

    if ('nominationStarted' in opts) {
      if (!!opts.nominationStarted !== !!context.nominationStarted) {
        context.nominationStarted = !!opts.nominationStarted;
        has_changed = true;
      }
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


    /* Consent success tracking */

    if ('consentLastSuccessAt' in opts) {
      if (opts.consentLastSuccessAt !== context.consentLastSuccessAt) {
        context.consentLastSuccessAt = opts.consentLastSuccessAt;
        has_changed = true;
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
        const batch = context.localCandidates.slice().sort(function(a, b) {
          return b.priority - a.priority;
        });
        for (let i = 0; i < batch.length; i++) ev.emit('candidate', maskCandidateForSignaling(batch[i]));
      }
      ev.emit('candidate', null);
    }


    /* 2.2 — Enter 'checking' when creds + pairs are ready (full mode).
     *  Runs when:
     *    - state='new' (fresh connection)
     *    - state='connected' with _previousPair set (ICE restart, RFC 8445 §9):
     *      old pair keeps forwarding media while we negotiate a new selection
     */
    if ((context.state === 'new' ||
         (context.state === 'connected' && context._previousPair)) &&
        context.mode !== 'lite' &&
        context.remoteUfrag && context.remotePwd &&
        context.localCandidates.length > 0 &&
        context.remoteCandidates.length > 0 &&
        context.checkList.length > 0 &&
        !context.selectedPair) {
      params_to_set.state = 'checking';
    }


    /* 2.3 — Start the check scheduler tick when state='checking' and ready.
     *        Same prerequisites as 2.2 — we need creds + candidates + pairs.
     *        This way, artificially setting state='checking' without inputs
     *        doesn't launch a tick that would immediately fail. */
    if (context.state === 'checking' &&
        !context.checkTimer &&
        !context.selectedPair &&
        context.mode !== 'lite' &&
        context.remoteUfrag && context.remotePwd &&
        context.localCandidates.length > 0 &&
        context.remoteCandidates.length > 0 &&
        context.checkList.length > 0 &&
        !context.closed) {
      initiateChecks();   // imperative: unfreeze pairs, setInterval(runCheckTick)
    }


    /* 2.4 — Schedule nomination when controlling + first valid pair appears */
    if (context.controlling &&
        context.mode !== 'lite' &&
        !context.nominationStarted &&
        !context.selectedPair &&
        context.validList.length > 0 &&
        !context.closed) {
      initiateNominationTimer();   // imperative: setTimeout → nominatePair()
      params_to_set.nominationStarted = true;
    }


    /* 2.5 — Auto-select: the highest-priority nominated-and-valid pair.
     *
     * NOT first-past-the-post: under aggressive nomination (RFC 5245-era
     * behavior that pion/webrtc-rs still use — USE-CANDIDATE on every
     * check) several pairs become nominated, and WHICH validates first is
     * a network race. If we lock the first one while the peer selects by
     * priority, the two sides can settle on different 5-tuples — observed
     * live against webrtc-rs, whose srflx gathering socket is distinct
     * from its advertised host socket: we locked the peer-reflexive pair
     * (their srflx-base), their DTLS sat on their host socket, and the
     * ClientHello went into a void. Both RFC 5245 §8.1.1.2 semantics and
     * libwebrtc/pion practice: the controlled side keeps converging to
     * the highest-priority nominated valid pair. The selectedPair setter
     * handles replacement (emits with prev, retargets primarySocket). */
    if (!context.closed) {
      let best = context.selectedPair || null;
      for (let i = 0; i < context.validList.length; i++) {
        const p = context.validList[i];
        if (!p.valid || !p.nominated) continue;
        if (!best || p.priority > best.priority) best = p;
      }
      if (best && best !== context.selectedPair) {
        params_to_set.selectedPair = best;
        // ICE restart complete — drop the previous pair; new selectedPair
        // (assigned by the recursive set_context call) takes over send().
        if (context._previousPair) {
          context._previousPair = null;
        }
      }
    }


    /* 2.6 — Once selected, transition state to 'connected' */
    // 'disconnected' is excluded alongside 'failed' and 'closed'. It is a
    // consent-freshness verdict (RFC 7675), not a checklist verdict: the pair
    // is still selected and still valid as far as the checklist knows, so
    // without this exclusion every set_context({state:'disconnected'}) was
    // undone by the very cascade run it triggered. The state oscillated
    // disconnected -> connected forever and a dead peer never latched.
    //
    // Recovery is owned by consentTick, which sets 'connected' again itself
    // once a consent response arrives and the age drops back under the
    // threshold. That is the only place that knows the path came back.
    if (context.selectedPair &&
        context.state !== 'connected' &&
        context.state !== 'disconnected' &&
        context.state !== 'failed' &&
        context.state !== 'closed') {
      params_to_set.state = 'connected';
    }


    /* 2.7 — Stop the check scheduler once selected AND settled: while a
     * higher-priority pair could still validate (waiting / in-progress /
     * frozen), checks must continue or cascade 2.5's convergence can
     * never happen — the upgrade pair only becomes `valid` through OUR
     * completed check. Terminates: such pairs either succeed (upgrade,
     * then no higher pair remains) or fail (leave the set); the global
     * 45s policy bounds the whole phase. */
    if (context.selectedPair) {
      let upgradePossible = false;
      for (let i = 0; i < context.checkList.length; i++) {
        const p = context.checkList[i];
        if (p === context.selectedPair) continue;
        if (p.priority <= context.selectedPair.priority) continue;
        if (p.state === 'waiting' || p.state === 'in-progress' || p.state === 'frozen') {
          upgradePossible = true;
          break;
        }
      }
      if (!upgradePossible) {
        if (context.checkTimer) {
          clearInterval(context.checkTimer);
          context.checkTimer = null;
        }
        if (context.triggeredQueue && context.triggeredQueue.length > 0) {
          context.triggeredQueue.length = 0;
        }
      }
    }


    /* 2.8 — Once selected, start consent freshness (RFC 7675) */
    // Gated on consentActive, NOT on consentTimer. The handle is legitimately
    // null for the duration of a tick (consentTick nulls it on entry), so
    // gating on it made every state change that happened inside a tick look
    // like "consent is not running" and restart the cycle.
    //
    // That was fatal for the one transition that matters: consentTick detects
    // a dead path, sets 'disconnected', set_context re-runs this cascade, the
    // cascade sees a null handle and calls initiateConsentFreshness, which
    // resets consentLastSuccessAt — erasing the very evidence that produced
    // the disconnect. The state flipped straight back to 'connected' and did
    // so forever; 'failed' was unreachable, and a second consent timer was
    // scheduled on every cycle. A dead peer stayed 'connected' indefinitely.
    if (context.selectedPair &&
        !context.consentActive &&
        context.mode !== 'lite' &&
        !context.closed) {
      initiateConsentFreshness();   // imperative: schedules first consentTick
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

  function findLocalCandidate(ip, port) {
    for (let i = 0; i < context.localCandidates.length; i++) {
      const c = context.localCandidates[i];
      if (c.ip === ip && c.port === port) return c;
    }
    return null;
  }

  function findRemoteCandidate(ip, port) {
    for (let i = 0; i < context.remoteCandidates.length; i++) {
      const c = context.remoteCandidates[i];
      if (c.ip === ip && c.port === port) return c;
    }
    return null;
  }

  function recomputePairPriorities() {
    // After role change, priorities must be recomputed and list re-sorted
    for (let i = 0; i < context.checkList.length; i++) {
      const p = context.checkList[i];
      p.priority = computePairPriority(context.controlling, p.local.priority, p.remote.priority);
    }
    context.checkList.sort((a, b) => b.priority - a.priority);
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
    if (context.iceTransportPolicy === 'relay') return;
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
   * Mirror of runCheckTick's terminal condition, for the moment the last
   * pending mDNS resolution fails: if the check scheduler already stopped
   * (or never started) and nothing valid exists, the ICE session is dead.
   * While pendingResolves > 0 this never fires — a resolution in flight
   * can still create pairs.
   */
  function maybeFailAfterMdns() {
    if (context.mdns.pendingResolves > 0) return;
    if (context.state !== 'checking') return;
    if (context.checkTimer) return;      // scheduler alive — it will decide
    if (context.selectedPair) return;
    const anyActive = context.checkList.some((p) =>
      p.state === 'waiting' || p.state === 'in-progress' || p.state === 'frozen');
    if (anyActive) return;
    const anyValid = context.checkList.some((p) => p.valid);
    if (!anyValid) set_context({ state: 'failed' });
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
    if (!c || !context.mdns.register) return c;
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
      state:           'frozen',    // frozen | waiting | in-progress | succeeded | failed
      valid:           false,

      // Nomination tracking (Part 2b)
      nominated:       false,       // both sides agree — pair is the chosen one
      peerNominated:   false,       // remote sent USE-CANDIDATE on this pair
      weNominated:     false,       // we (controlling) sent USE-CANDIDATE on this pair

      retransmits:     0,
      transactionId:   null,
      lastSent:        0,
      encodedCheck:    null,

      // ── Stats counters (W3C RTCIceCandidatePairStats) ───────────────────
      // Populated by sendBindingCheck/sendConsentCheck/onCheckResponse and
      // by handleBindingRequest. Zero-valued until first activity.
      roundTripTime:      0,        // seconds, last measured (response - request)
      totalRoundTripTime: 0,        // seconds, sum of all measurements
      rttMeasurements:    0,        // count of successful response arrivals
      requestsSent:       0,        // connectivity checks we sent
      responsesReceived:  0,        // responses to our checks
      requestsReceived:   0,        // peer's connectivity checks we got
      responsesSent:      0,        // our responses to peer's checks
      consentRequestsSent: 0,       // consent keepalives we sent
      bytesSent:          0,        // STUN bytes sent on this pair
      bytesReceived:      0,        // STUN bytes received on this pair
      packetsSent:        0,        // STUN packets sent on this pair
      packetsReceived:    0,        // STUN packets received on this pair
      lastPacketSentTimestamp:     0,
      lastPacketReceivedTimestamp: 0,
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


  /* ========================= Gathering ========================= */

  function startGathering() {
    if (context._gathering_host) return;
    context._gathering_host = true;

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
        const existing = context.localCandidates.slice().sort(function(a, b) {
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
            // All optional: the Socket falls back to import('lemon-tls') and
            // the global WebSocket respectively when these are absent.
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
    const relayOnly = (context.iceTransportPolicy === 'relay');

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

  function addHostFromBoundSocket(sock, boundAddr) {
    const key = boundAddr.family + ':' + boundAddr.address + ':' + boundAddr.port;
    if (context.sockets[key]) return;
    context.sockets[key] = sock;
    if (!context.primarySocket) context.primarySocket = sock;

    // Relay-only policy: bind the socket (needed as TURN allocate base) but
    // do NOT expose the host candidate externally. RFC 8445 §5.1.1.2 allows
    // filtering candidates; WebRTC's `iceTransportPolicy: 'relay'` mandates
    // that only relay candidates be gathered and used.
    if (context.iceTransportPolicy === 'relay') return;

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
      const sock = dgram.createSocket({ type, reuseAddr: true });

      sock.on('message', function(buf, rinfo) {
        // HOT PATH: Node dgram delivers Buffer (a Uint8Array subclass).
        // Skip new Uint8Array(buf) — it only allocates a view object.
        onSocketMessage(buf, rinfo, sock);
      });

      sock.on('error', function(err) {
        try {
          var _ea = sock.address();
          console.log('[ice-diag] ' + _diagTs() + ' SOCKET ERROR on ' +
                      _ea.address + ':' + _ea.port + ' — ' + (err && err.message));
        } catch (e) {
          console.log('[ice-diag] ' + _diagTs() + ' SOCKET ERROR (unbound) — ' + (err && err.message));
        }
        ev.emit('error', err);
      });

      sock.on('close', function() {
        // Bound identity is unreadable post-close; capture at bind below.
        console.log('[ice-diag] ' + _diagTs() + ' SOCKET CLOSED ' +
                    (sock.__diagBound || '(identity unknown)'));
      });

      sock.on('listening', function() {
        // success
      });

      sock.bind({ address: ip, port: 0, exclusive: false }, function() {
        let bound;
        try { bound = sock.address(); } catch (e) { cb(null, null); return; }
        sock.__diagBound = bound.address + ':' + bound.port;
        console.log('[ice-diag] ' + _diagTs() + ' SOCKET BOUND ' + sock.__diagBound);
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

    const timer = setTimeout(function() {
      finish(new Error('STUN timeout'));
    }, GATHER_SRFLX_TIMEOUT_MS);
    context._gather_timers.add(timer);
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
          // DTLS transport (lemon-tls) — injection optional; Socket falls back
          // to import('lemon-tls') when these are absent.
          connectDTLS:        server.connectDTLS || null,
          lemonTls:           server.lemonTls    || null,
          alpnProtocols:      server.alpnProtocols || null,
          minVersion:         server.minVersion  || null,
          maxVersion:         server.maxVersion  || null,
          mtu:                server.mtu         || null,
          // WebSocket transport — injection optional; Socket falls back to the
          // global WebSocket (Node >= 22).
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
      // DTLS / RTP / RTCP / channel-data — forward
      ev.emit('packet', buf, rinfo, type);
    }
  }

  function onTurnRelayedData(buf, peerIp, peerPort, turnSocket) {
    if (context.closed) return;
    const type = wire.demux(buf);
    // HOT PATH: RTP/RTCP/DTLS is 99% of traffic on an established call.
    // Avoid allocating rinfo object in that case — consumers rarely need
    // `family` for media packets; we synthesize it only for STUN.
    if (type === 'stun') {
      const rinfo = { address: peerIp, port: peerPort, family: addressFamilyOf(peerIp) };
      handleStunMessage(buf, rinfo, null, turnSocket);
    } else {
      // Lightweight rinfo without family computation (not needed for media demux).
      ev.emit('packet', buf, { address: peerIp, port: peerPort }, type);
    }
  }

  function handleStunMessage(buf, rinfo, sock, turnSocket) {
    // [ice-diag] FUNNEL ENTRY: every datagram classified as STUN logs its
    // arrival (rate-limited per source). Combined with the outcome logs
    // below, a disconnect investigation can now distinguish in one run:
    // never-arrived (no stun-rx) / arrived-but-unparseable (DECODE FAILED)
    // / parsed-but-dropped (validation 401s) / handled.
    if (_diagRL('stunrx:' + rinfo.address + ':' + rinfo.port, 2000)) {
      var _lsock = '?';
      try { if (sock) { var _la = sock.address(); _lsock = _la.address + ':' + _la.port; } } catch (e) {}
      console.log('[ice-diag] ' + _diagTs() + ' stun-rx from ' +
                  rinfo.address + ':' + rinfo.port + ' → local ' + _lsock +
                  ' len=' + buf.length);
    }
    const msg = wire.decode_message(buf);
    if (!msg) {
      if (_diagRL('stundecfail:' + rinfo.address + ':' + rinfo.port, 2000)) {
        console.log('[ice-diag] ' + _diagTs() + ' stun-rx DECODE FAILED from ' +
                    rinfo.address + ':' + rinfo.port + ' len=' + buf.length +
                    ' head=' + buf.slice(0, 8).toString('hex'));
      }
      return;
    }
    const txHex = txIdHex(msg.transactionId);

    // 1. Pending transaction (our outgoing STUN req — connectivity check, gather, etc.)
    const pending = context.pendingTransactions[txHex];
    if (pending) {
      if (_diagRL('stunresp:' + rinfo.address + ':' + rinfo.port, 5000)) {
        console.log('[ice-diag] ' + _diagTs() + ' stun response consumed (kind=' +
                    pending.kind + ') from ' + rinfo.address + ':' + rinfo.port);
      }
      if (msg.cls === wire.CLASS.SUCCESS) {
        // For checks and consent: validate MESSAGE-INTEGRITY with remote password
        if ((pending.kind === 'check' || pending.kind === 'consent') && context.remotePwd) {
          const validated = wire.validateStunMessage(buf, context.remotePwd);
          if (!validated) return;   // silently drop bad-integrity response (RFC 8445 §7.2.5.1)
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
          const validated = wire.validateStunMessage(buf, context.remotePwd);
          if (!validated) return;   // silently drop spoof attempts
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
    if (_diagRL('stunfall:' + rinfo.address + ':' + rinfo.port, 2000)) {
      console.log('[ice-diag] ' + _diagTs() + ' stun UNHANDLED from ' +
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

  function initiateChecks() {
    // Triggered by cascade 2.3 when state === 'checking' and no checkTimer.
    // Unfreeze all pairs (simplified — RFC 8445 §6.1.2.6 specifies
    // per-foundation unfreezing, but unfreeze-all is a safe superset).
    for (let i = 0; i < context.checkList.length; i++) {
      if (context.checkList[i].state === 'frozen') {
        context.checkList[i].state = 'waiting';
      }
    }
    context.checkTimer = setInterval(runCheckTick, CHECK_PACE_MS);
    if (context.checkTimer.unref) context.checkTimer.unref();
    // Run one immediately so the first check goes out without 50ms delay
    runCheckTick();
  }

  function unfreezePairsAfterSuccess(succeeded) {
    // After a pair completes, unfreeze all other pairs with the same
    // local+remote foundation (RFC 8445 §7.2.5.3.3).
    const fLocal = succeeded.local.foundation;
    const fRemote = succeeded.remote.foundation;
    for (let i = 0; i < context.checkList.length; i++) {
      const p = context.checkList[i];
      if (p.state !== 'frozen') continue;
      if (p.local.foundation === fLocal && p.remote.foundation === fRemote) {
        p.state = 'waiting';
      }
    }
  }


  /* ── Check scheduling tick ── */

  function runCheckTick() {
    if (context.closed) return;

    // Prefer 'triggered' checks (pairs put into the triggered queue by an
    // incoming Binding Request), then pick the highest-priority 'waiting' pair.
    // RFC 8445 §6.1.4.
    let next = null;
    if (context.triggeredQueue && context.triggeredQueue.length > 0) {
      next = context.triggeredQueue.shift();
    } else {
      const now = Date.now();
      for (let i = 0; i < context.checkList.length; i++) {
        const p = context.checkList[i];
        if (p.state !== 'waiting') continue;
        // Recoverable-error cooldown: the pair is active — which also
        // keeps the check timer alive below — but its next attempt is
        // not yet due (retry pacing for RFC 8445 §7.2.5.2.4 errors).
        if (p.retryAfter && p.retryAfter > now) continue;
        next = p;
        break;
      }
    }

    if (!next) {
      // No pairs to check right now — check if we should stop the timer
      const anyActive = context.checkList.some((p) =>
        p.state === 'waiting' || p.state === 'in-progress' || p.state === 'frozen');
      if (!anyActive) {
        clearInterval(context.checkTimer);
        context.checkTimer = null;
        // All pairs terminated — if none succeeded, we fail.
        // Nomination → 'connected' is Part 2b, so for now we stay in 'checking'
        // when pairs succeed.
        // Exception: an in-flight mDNS resolution can still create new
        // pairs — hold off; finishMdnsResolve → maybeFailAfterMdns picks
        // this up when the last one lands.
        const anyValid = context.checkList.some((p) => p.valid);
        if (!anyValid && context.mdns.pendingResolves === 0) {
          set_context({ state: 'failed' });
        }
      }
      return;
    }

    sendBindingCheck(next);
  }


  /* ── Outgoing connectivity check ── */

  function sendBindingCheck(pair) {
    if (context.closed) return;
    if (!context.remoteUfrag || !context.remotePwd) return;

    const sock = getSocketForLocalCandidate(pair.local);
    if (!sock && !pair.local.turnClient) {
      pair.state = 'failed';
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
    if (context.controlling) {
      attrs.push({ type: wire.ATTR.ICE_CONTROLLING, value: context.tieBreaker });
    } else {
      attrs.push({ type: wire.ATTR.ICE_CONTROLLED, value: context.tieBreaker });
    }
    // Part 2b: Regular nomination — controlling agent marks this pair as the
    // chosen one by attaching USE-CANDIDATE. Only set for the dedicated
    // nomination re-check (pair.weNominated flag was set by startNomination).
    if (pair.weNominated) {
      attrs.push({ type: wire.ATTR.USE_CANDIDATE, value: null });
    }

    const key = wire.compute_short_term_key(context.remotePwd);
    const encoded = wire.encode_message({
      method:      wire.METHOD.BINDING,
      cls:         wire.CLASS.REQUEST,
      attributes:  attrs,
      key:         key,
      fingerprint: true,
    });

    const txHex = txIdHex(encoded.transactionId);
    pair.transactionId = encoded.transactionId;
    pair.lastSent      = Date.now();
    pair.state         = 'in-progress';
    pair.retransmits   = 0;
    pair.encodedCheck  = encoded.buf;   // saved for retransmits

    // Stats: count this binding request (before send — we want to count the
    // attempt even if transmission fails). Retransmits are counted on their
    // own path (scheduleRetransmit).
    pair.requestsSent++;
    pair.bytesSent        += encoded.buf.length;
    pair.packetsSent++;
    pair.lastPacketSentTimestamp = pair.lastSent;

    context.pendingTransactions[txHex] = {
      kind:     'check',
      pair:     pair,
      callback: function(msg, rinfo, err) {
        // Remove from pending on first response (callback is one-shot)
        delete context.pendingTransactions[txHex];
        if (pair.retransmitTimer) { clearTimeout(pair.retransmitTimer); pair.retransmitTimer = null; }
        onCheckResponse(pair, msg, rinfo, err);
      },
    };

    sendStunToRemote(pair.local, pair.remote, encoded.buf);
    scheduleRetransmit(pair, txHex);
  }

  function scheduleRetransmit(pair, txHex) {
    const pending = context.pendingTransactions[txHex];
    if (!pending) return;

    // RFC 8445 §14.3 / RFC 5389 §7.2.1 — RTO doubles, max 7 retransmits.
    // Simplification: RTO starts at STUN_INITIAL_RTO_UDP (500ms) and doubles.
    const rto = STUN_INITIAL_RTO_UDP * Math.pow(2, pair.retransmits);

    pair.retransmitTimer = setTimeout(function() {
      if (context.closed) return;
      if (!context.pendingTransactions[txHex]) return;   // already resolved

      if (pair.retransmits >= STUN_RC) {
        // All retransmits exhausted — final wait for one more RTO * RM, then fail.
        delete context.pendingTransactions[txHex];
        pair.retransmitTimer = null;
        onCheckResponse(pair, null, null, new Error('Check timeout'));
        return;
      }

      pair.retransmits++;
      sendStunToRemote(pair.local, pair.remote, pair.encodedCheck);
      scheduleRetransmit(pair, txHex);
    }, rto);

    if (pair.retransmitTimer.unref) pair.retransmitTimer.unref();
  }

  function onCheckResponse(pair, msg, rinfo, err) {
    if (context.closed) return;

    if (err) {
      // STUN error responses — RFC 8445 §7.2.5.2.4: a pair is failed only
      // on an *unrecoverable* [RFC5389] error. The recoverable set below
      // mirrors Chrome's libwebrtc (p2p/base/connection.cc,
      // OnConnectionRequestErrorResponse): 401 Unauthorized, 420 Unknown
      // Attribute, and 500 Server Error are answered with a retry —
      // "Recoverable error, retry" — because they are routinely transient.
      // The canonical case: our connectivity checks legitimately race the
      // peer's processing of our answer (trickle ICE), and until the peer
      // learns our ufrag it rejects checks with 401 (RFC 5389 §10.1.2).
      // Failing the pair on that race — as this code previously did for
      // every non-487 code — killed otherwise-perfect connections within
      // one RTT. pion/ice goes further and discards error responses
      // entirely, retrying until its global timeout; we take libwebrtc's
      // middle path. The retry is paced by returning the pair to
      // 'waiting' after ~half the STUN RTO, and remains bounded by the
      // agent's overall failure policy, so a peer that answers 401
      // forever still converges to 'failed'.
      //
      // Anything else — including 400 — stays fatal, exactly as in
      // libwebrtc ("killing connection"). Note: werift ≤0.15 rejects
      // pre-answer checks with 400 where RFC 5389 §10.1.2 mandates 401;
      // such peers fail against Chrome for the same reason.
      if (msg) {
        const ec = msg.getAttribute(wire.ATTR.ERROR_CODE);
        if (ec && ec.code === 487) {
          // 487 role conflict → switch role, re-queue check
          handleRoleConflictFromResponse(pair);
          return;
        }
        if (ec && (ec.code === 401 || ec.code === 420 || ec.code === 500)) {
          // Return the pair to the scheduler immediately, with a cooldown
          // stamp the tick loop honors. Doing this synchronously — rather
          // than via a detached timer — keeps the pair in 'waiting' at all
          // times, so runCheckTick's no-active-pairs branch can never tear
          // down the check timer (and declare failure) in the window
          // between the error response and the retry becoming due.
          pair.state = 'waiting';
          pair.retryAfter = Date.now() + 250;   // ~½ STUN RTO (RFC 5389 §7.2.1)
          return;
        }
      }
      pair.state = 'failed';
      set_context({ pair_failed: pair });
      return;
    }

    // Stats: record RTT, byte/packet counters for this response.
    // RFC 7064 / RFC 8445 — RTT is (response arrival) - (request send).
    const nowMs = Date.now();
    if (pair.lastSent) {
      const rttMs = nowMs - pair.lastSent;
      pair.roundTripTime      = rttMs / 1000;           // seconds (spec format)
      pair.totalRoundTripTime += rttMs / 1000;
      pair.rttMeasurements++;
    }
    pair.responsesReceived++;
    pair.packetsReceived++;
    // Best-effort — msg.raw length, else approximate by the MI-truncated header.
    pair.bytesReceived += (msg && msg.raw && msg.raw.length) ? msg.raw.length : 20;
    pair.lastPacketReceivedTimestamp = nowMs;

    // Validate XOR-MAPPED-ADDRESS presence (RFC 8489)
    const mapped = msg.getAttribute(wire.ATTR.XOR_MAPPED_ADDRESS)
                || msg.getAttribute(wire.ATTR.MAPPED_ADDRESS);
    if (!mapped) {
      pair.state = 'failed';
      set_context({ pair_failed: pair });
      return;
    }

    const mappedIp   = mapped.ip || mapped.address;
    const mappedPort = mapped.port;

    // ─ RFC 8445 §7.2.5.3 — "Constructing the Valid Pair" ─
    //
    // The valid pair is formed from:
    //   - validLocal:  the local candidate whose transport address EQUALS
    //                  the mapped address in the STUN response
    //   - validRemote: pair.remote (the candidate we sent the check to)
    //
    // If the mapped address matches no known local candidate, it's a new
    // peer-reflexive local candidate — we MUST create it first, THEN form
    // a valid pair with (prflx, pair.remote) rather than marking the
    // ORIGINAL pair valid. The original pair is still 'succeeded' (the
    // check succeeded) but not necessarily 'valid'.
    let validLocal = pair.local;
    if (mappedIp !== pair.local.ip || mappedPort !== pair.local.port) {
      // NAT mapped us differently — look up or create peer-reflexive local.
      validLocal = findLocalCandidate(mappedIp, mappedPort)
                || addPeerReflexiveLocal(mappedIp, mappedPort, pair.local);
    }

    // The ORIGINAL pair's check succeeded — mark state succeeded (so we
    // don't re-check it) and unfreeze same-foundation pairs.
    pair.state = 'succeeded';
    unfreezePairsAfterSuccess(pair);

    // Find or create the VALID pair — the one actually added to the valid list.
    let validPair;
    if (validLocal === pair.local) {
      // Normal case — same address, original pair is valid.
      validPair = pair;
    } else {
      // Peer-reflexive — form a new pair (or reuse if already exists).
      validPair = findPair(validLocal, pair.remote);
      if (!validPair) {
        validPair = tryMakePair(validLocal, pair.remote);
      }
      if (!validPair) {
        // Couldn't make pair (shouldn't happen) — fall back to original.
        validPair = pair;
      } else {
        // The new prflx-based pair is succeeded by virtue of the check
        // that just succeeded, per §7.2.5.3.3.
        validPair.state = 'succeeded';
      }
    }

    validPair.valid = true;

    // Nomination inheritance from the triggering pair:
    // RFC 8445 §7.2.5.3.4 — if the original check had USE-CANDIDATE (we
    // nominated) OR the peer had nominated it earlier, those flags apply
    // to the valid pair we just constructed.
    if (pair.weNominated    && !validPair.weNominated)    validPair.weNominated    = true;
    if (pair.peerNominated  && !validPair.peerNominated)  validPair.peerNominated  = true;
    if (validPair.weNominated || validPair.peerNominated) {
      validPair.nominated = true;
    }

    // Notify set_context — cascades decide: add to validList, emit paircheck,
    // schedule nomination timer (if needed), auto-select (if nominated), etc.
    set_context({ pair_validated: validPair });
  }


  /* ── Imperative helpers: nomination + consent (called from cascades) ── */
  //
  // These DO NOT decide state. They perform side effects (schedule timers,
  // send STUN). When events arrive, they feed results BACK via set_context,
  // which re-evaluates the cascades in Phase 2.

  function initiateNominationTimer() {
    // Triggered by cascade 2.4: controlling + first valid pair appeared.
    // Wait NOMINATION_DELAY_MS so more pairs may become valid and we nominate
    // the actual best (not just the first).
    if (context.nominationTimer) return;
    context.nominationTimer = setTimeout(fireNomination, NOMINATION_DELAY_MS);
    if (context.nominationTimer.unref) context.nominationTimer.unref();
  }

  function fireNomination() {
    context.nominationTimer = null;
    if (context.closed) return;
    if (!context.controlling) return;
    if (context.selectedPair) return;   // someone else beat us to it

    // Pick the highest-priority valid pair that we haven't already nominated.
    const candidates = context.validList.filter((p) => !p.weNominated);
    if (candidates.length === 0) {
      // No candidate — reset flag so next validation retriggers timer.
      set_context({ nominationStarted: false });
      return;
    }
    let best = candidates[0];
    for (let i = 1; i < candidates.length; i++) {
      if (candidates[i].priority > best.priority) best = candidates[i];
    }

    // Mark and re-queue for another check carrying USE-CANDIDATE.
    best.weNominated = true;
    best.state = 'waiting';
    if (context.triggeredQueue.indexOf(best) < 0) {
      context.triggeredQueue.push(best);
    }
    // Nudge immediately so nomination doesn't wait for next Ta tick.
    runCheckTick();
  }


  function initiateConsentFreshness() {
    // Triggered by cascade 2.8: selectedPair set, not lite, not already running.
    if (context.consentActive) return;
    context.consentActive = true;
    context.consentLastSuccessAt = Date.now();
    scheduleNextConsentTick();
  }

  function scheduleNextConsentTick() {
    if (context.closed) return;
    const jitter = 1 + (Math.random() * 2 - 1) * CONSENT_RANDOMIZATION;
    const ms = Math.floor(CONSENT_INTERVAL_MS * jitter);
    context.consentTimer = setTimeout(consentTick, ms);
    if (context.consentTimer.unref) context.consentTimer.unref();
  }

  function consentTick() {
    context.consentTimer = null;
    if (context.closed || !context.selectedPair) return;

    // Decide lifecycle transition based on last-success age.
    const age = Date.now() - context.consentLastSuccessAt;

    // [ice-diag] every tick: shows the cadence, the last-success age, and
    // the exact 5-tuple our consent goes to. If the path silently died,
    // age climbs here tick after tick while everything else looks normal.
    if (_ICE_DBG) {
      const _p = context.selectedPair;
      console.log('[ice-diag] ' + _diagTs() + ' consent-tick age=' + age + 'ms → ' +
                  (_p.remote && _p.remote.ip) + ':' + (_p.remote && _p.remote.port) +
                  ' (from ' + (_p.local && _p.local.ip) + ':' + (_p.local && _p.local.port) + ')' +
                  ' state=' + context.state);
    }

    if (age >= CONSENT_FAILED_MS) {
      // Terminal. consentActive stays TRUE deliberately: clearing it here
      // would let cascade 2.8 immediately start a fresh cycle against the
      // same dead pair, which restarts the ticks and resets the age — the
      // failure would not stay latched. The flag is cleared by teardown and
      // by ICE restart, which are the only paths that can produce a pair
      // worth checking again.
      set_context({ state: 'failed' });
      return;   // stop scheduling further
    }
    if (age >= CONSENT_DISCONNECT_MS) {
      if (context.state === 'connected') set_context({ state: 'disconnected' });
    } else if (context.state === 'disconnected') {
      set_context({ state: 'connected' });   // recovery
    }

    // Send a new consent check; response updates consentLastSuccessAt via set_context.
    sendConsentCheck(context.selectedPair);
    scheduleNextConsentTick();
  }

  function sendConsentCheck(pair) {
    if (context.closed) return;
    if (!context.remoteUfrag || !context.remotePwd) return;

    // Same format as a connectivity check, but:
    //   - no USE-CANDIDATE (nomination already done)
    //   - no state mutation on pair (pair is already selected)
    //   - no retransmits (periodic cadence handles loss detection)
    const username = context.remoteUfrag + ':' + context.localUfrag;
    const prflxPriority = computeCandidatePriority('prflx', LOCAL_PREFERENCE_DEFAULT, pair.local.component);

    const attrs = [
      { type: wire.ATTR.USERNAME, value: username },
      { type: wire.ATTR.PRIORITY, value: prflxPriority },
    ];
    if (context.controlling) attrs.push({ type: wire.ATTR.ICE_CONTROLLING, value: context.tieBreaker });
    else                     attrs.push({ type: wire.ATTR.ICE_CONTROLLED,  value: context.tieBreaker });

    const key = wire.compute_short_term_key(context.remotePwd);
    const encoded = wire.encode_message({
      method:      wire.METHOD.BINDING,
      cls:         wire.CLASS.REQUEST,
      attributes:  attrs,
      key:         key,
      fingerprint: true,
    });

    const txHex = txIdHex(encoded.transactionId);
    const consentSentAt = Date.now();
    const timer = setTimeout(function() {
      const p = context.pendingTransactions[txHex];
      if (!p) return;
      delete context.pendingTransactions[txHex];
      if (p.callback) p.callback(null, null, new Error('consent timeout'));
    }, 10_000);
    if (timer.unref) timer.unref();

    // Stats — count the consent attempt on the selected pair.
    pair.consentRequestsSent++;
    pair.requestsSent++;
    pair.bytesSent += encoded.buf.length;
    pair.packetsSent++;
    pair.lastPacketSentTimestamp = consentSentAt;

    context.pendingTransactions[txHex] = {
      kind: 'consent',
      pair: pair,
      timer: timer,
      callback: function(msg, _rinfo, err) {
        delete context.pendingTransactions[txHex];
        if (timer) clearTimeout(timer);
        if (err) {
          // [ice-diag] a consent timeout is the smoking gun for a dead
          // server→peer (request) or peer→server (response) leg.
          if (_ICE_DBG) {
            console.log('[ice-diag] ' + _diagTs() + ' consent TIMEOUT (no response in 10s)');
          }
          return;   // no response → leave lastSuccessAt stale
        }
        if (_diagRL('consent-ok', 4000)) {
          console.log('[ice-diag] ' + _diagTs() + ' consent response OK');
        }
        // Stats: RTT from consent response + byte/packet counters.
        const rttMs = Date.now() - consentSentAt;
        pair.roundTripTime       = rttMs / 1000;
        pair.totalRoundTripTime += rttMs / 1000;
        pair.rttMeasurements++;
        pair.responsesReceived++;
        pair.packetsReceived++;
        pair.bytesReceived += (msg && msg.raw && msg.raw.length) ? msg.raw.length : 20;
        pair.lastPacketReceivedTimestamp = Date.now();
        // Successful response → feed back through set_context so cascades re-run.
        set_context({ consentLastSuccessAt: Date.now() });
      },
    };

    sendStunToRemote(pair.local, pair.remote, encoded.buf);
  }

  function handleBindingRequest(buf, msg, rinfo, sock, turnSocket) {
    if (context.closed) return;

    // Verify USERNAME and MESSAGE-INTEGRITY with OUR password (RFC 8445 §7.3)
    // [ice-diag] Every drop branch below LOGS (rate-limited): a silent
    // validation failure looks identical to "packets stopped arriving"
    // from the outside, and that ambiguity cost a full debugging session
    // (bidi disconnect hunt, Aug 2026). Never again.
    if (!context.localPwd) {
      if (_diagRL('drop-nopwd:' + rinfo.address + ':' + rinfo.port, 2000)) {
        console.log('[ice-diag] ' + _diagTs() + ' DROP binding-req from ' +
                    rinfo.address + ':' + rinfo.port + ' — context.localPwd is EMPTY');
      }
      return;
    }
    const validated = wire.validateStunMessage(buf, context.localPwd);
    if (!validated) {
      if (_diagRL('drop-integrity:' + rinfo.address + ':' + rinfo.port, 2000)) {
        console.log('[ice-diag] ' + _diagTs() + ' 401 binding-req from ' +
                    rinfo.address + ':' + rinfo.port + ' — MESSAGE-INTEGRITY failed ' +
                    '(their HMAC pwd != our context.localPwd — credential divergence?)');
      }
      sendBindingError(msg, rinfo, sock, turnSocket, 401, 'Unauthenticated');
      return;
    }

    // USERNAME must be "<our-ufrag>:<their-ufrag>"
    const usernameAttr = msg.getAttribute(wire.ATTR.USERNAME);
    if (typeof usernameAttr !== 'string' || usernameAttr.indexOf(':') < 0) {
      if (_diagRL('drop-badusr:' + rinfo.address + ':' + rinfo.port, 2000)) {
        console.log('[ice-diag] ' + _diagTs() + ' 400 binding-req from ' +
                    rinfo.address + ':' + rinfo.port + ' — malformed USERNAME');
      }
      sendBindingError(msg, rinfo, sock, turnSocket, 400, 'Bad Request');
      return;
    }
    const colonIdx = usernameAttr.indexOf(':');
    const usernameLocal = usernameAttr.substring(0, colonIdx);
    if (usernameLocal !== context.localUfrag) {
      if (_diagRL('drop-ufrag:' + rinfo.address + ':' + rinfo.port, 2000)) {
        console.log('[ice-diag] ' + _diagTs() + ' 401 binding-req from ' +
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
        if (_diagRL('roleconf:' + rinfo.address + ':' + rinfo.port, 2000)) {
          console.log('[ice-diag] ' + _diagTs() + ' 487 ROLE CONFLICT (both controlling, we win) → ' +
                      rinfo.address + ':' + rinfo.port + ' — our role=controlling');
        }
        sendBindingError(msg, rinfo, sock, turnSocket, 487, 'Role Conflict');
        return;
      }
      // We lose — switch to controlled
      console.log('[ice-diag] ' + _diagTs() + ' role conflict: both controlling, we LOSE → switching to controlled');
      switchRole(false);
    } else if (!context.controlling && icControlled !== null) {
      // Both claim controlled
      if (compareTieBreakers(context.tieBreaker, icControlled.raw) >= 0) {
        if (_diagRL('roleconf:' + rinfo.address + ':' + rinfo.port, 2000)) {
          console.log('[ice-diag] ' + _diagTs() + ' 487 ROLE CONFLICT (both controlled, we win) → ' +
                      rinfo.address + ':' + rinfo.port + ' — our role=controlled');
        }
        sendBindingError(msg, rinfo, sock, turnSocket, 487, 'Role Conflict');
        return;
      }
      console.log('[ice-diag] ' + _diagTs() + ' role conflict: both controlled, we LOSE → switching to controlling');
      switchRole(true);
    }

    // Find or create remote candidate (peer-reflexive if new)
    let remoteCand = findRemoteCandidate(rinfo.address, rinfo.port);
    if (!remoteCand) {
      const priorityAttr = msg.getAttribute(wire.ATTR.PRIORITY);
      const prflxPriority = priorityAttr || computeCandidatePriority('prflx', LOCAL_PREFERENCE_DEFAULT, COMPONENT_RTP);
      remoteCand = addPeerReflexiveRemote(rinfo.address, rinfo.port, prflxPriority);
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
    }

    // Always respond — even before processing, the peer needs a Success
    // [ice-diag] Log request+response per source (max 1/2s per source):
    // proves whether the peer's checks/consent keep arriving and that we
    // keep answering — and to WHICH address the answer goes.
    if (_diagRL('bindreq:' + rinfo.address + ':' + rinfo.port, 2000)) {
      console.log('[ice-diag] ' + _diagTs() + ' binding-req from ' +
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
    if (hasUseCandidate) pair.peerNominated = true;

    // RFC 8445 §7.3.1.4: Triggered check — queue a check from our side for
    // this pair, unless it's already in-flight or already succeeded.
    if (pair.state !== 'succeeded' && pair.state !== 'in-progress') {
      pair.state = 'waiting';
      if (context.triggeredQueue.indexOf(pair) < 0) {
        context.triggeredQueue.push(pair);
      }
    }

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

    // Full: if pair was previously valid (our outgoing check succeeded earlier)
    // and peer just nominated it via USE-CANDIDATE, mark nominated — cascade
    // will pick up auto-selection.
    if (pair.valid && pair.peerNominated && !pair.nominated) {
      pair.nominated = true;
      set_context({ pair_validated: pair });
      return;
    }

    // Otherwise: pair was enqueued for a triggered check; kick cascades so
    // that (a) we transition to 'checking' if not yet there, (b) checkTimer
    // starts if not already running, (c) the triggered check goes out ASAP.
    set_context({ pair_triggered: pair });
  }


  /* ── Outgoing Binding responses ── */

  function sendBindingSuccess(req, rinfo, sock, turnSocket) {
    const key = wire.compute_short_term_key(context.localPwd);
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

  function sendBindingError(req, rinfo, sock, turnSocket, code, reason) {
    const encoded = wire.encode_message({
      method:        wire.METHOD.BINDING,
      cls:           wire.CLASS.ERROR,
      transactionId: req.transactionId,
      attributes: [
        { type: wire.ATTR.ERROR_CODE, value: { code: code, reason: reason } },
      ],
      fingerprint: true,
    });
    sendStunRaw(sock, turnSocket, rinfo, encoded.buf);
  }


  /* ── Role conflict handling ── */

  function handleRoleConflictFromResponse(pair) {
    // We sent with our role, got 487 back — we lose, flip.
    switchRole(!context.controlling);
    // Requeue the check
    pair.state = 'waiting';
    if (!context.triggeredQueue) context.triggeredQueue = [];
    if (context.triggeredQueue.indexOf(pair) < 0) {
      context.triggeredQueue.push(pair);
    }
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

  function addPeerReflexiveRemote(ip, port, priority) {
    // Check if already known
    for (let i = 0; i < context.remoteCandidates.length; i++) {
      const c = context.remoteCandidates[i];
      if (c.ip === ip && c.port === port) return c;
    }
    const cand = {
      foundation:     'prflx:' + ip + ':' + port,   // unknown; synthesize unique
      component:      COMPONENT_RTP,
      protocol:       'udp',
      priority:       priority,
      ip:             ip,
      port:           port,
      type:           'prflx',
      relatedAddress: null,
      relatedPort:    null,
      tcpType:        null,
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
        if (context.localCandidates[i].socket === sock) return context.localCandidates[i];
      }
    }
    if (turnSocket) {
      for (let i = 0; i < context.localCandidates.length; i++) {
        if (context.localCandidates[i].turnClient === turnSocket) return context.localCandidates[i];
      }
    }
    return context.localCandidates[0] || null;
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
    if (context.checkTimer)      { clearInterval(context.checkTimer);   context.checkTimer = null; }
    if (context.consentTimer)    { clearInterval(context.consentTimer); context.consentTimer = null; }
    context.consentActive = false;
    if (context.nominationTimer) { clearTimeout(context.nominationTimer); context.nominationTimer = null; }

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

    // Cancel pair retransmits
    for (let i = 0; i < context.checkList.length; i++) {
      const p = context.checkList[i];
      if (p.retransmitTimer) { clearTimeout(p.retransmitTimer); p.retransmitTimer = null; }
    }

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
    // STUN responses go back via the same family they arrived on.
    const isV6 = rinfo.family === 'IPv6';
    const sock = isV6 ? context.externalSocket6 : context.externalSocket;
    if (!sock) return;  // this family not configured

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
    get localCandidates()  { return context.localCandidates.map(maskCandidateForSignaling); },
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

      // Cancel any per-pair retransmit timers
      for (let i = 0; i < context.checkList.length; i++) {
        const p = context.checkList[i];
        if (p.retransmitTimer) { clearTimeout(p.retransmitTimer); p.retransmitTimer = null; }
      }

      // Cancel check scheduler and nomination timer.
      // Cancel consent timer too — the OLD session's consent check would
      // fail MESSAGE-INTEGRITY against the new remotePwd (which is null
      // until setRemoteParameters is called). The new selectedPair will
      // start its own consent via cascade 2.8 when it's chosen.
      if (context.checkTimer)      { clearInterval(context.checkTimer);   context.checkTimer = null; }
      if (context.nominationTimer) { clearTimeout(context.nominationTimer); context.nominationTimer = null; }
      if (context.consentTimer)    { clearTimeout(context.consentTimer);   context.consentTimer = null; }
      context.consentActive = false;   // the new selectedPair starts its own cycle

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
      context.triggeredQueue    = [];
      context.remoteCandidates  = [];
      context.remoteCandidatesEnded = false;
      context.nominationStarted = false;
      context._endOfCandidatesEmitted = false;

      // Local candidates are PRESERVED (their sockets carry _previousPair's
      // media). The next gather() re-announces them to the SDP layer —
      // add_local_candidate's dedup would otherwise swallow them.
      context._reEmitOnGather = true;

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
      console.log('[ice-diag] ' + _diagTs() + ' RESTART: local creds rotated ' +
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
        set_context({ state: 'new' });
      }

      ev.emit('restart', { ufrag, pwd });
      return { ufrag, pwd };
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