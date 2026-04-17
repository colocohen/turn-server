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
} from './ice_candidate.js';


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

  // Fallback: simple 'host:port' or 'scheme:host:port'
  let m = uri.match(/^(stun|stuns|turn|turns):(?:\/\/)?([^:?\/]+)(?::(\d+))?/);
  if (!m) return null;
  return {
    scheme: m[1],
    isTurn: m[1] === 'turn' || m[1] === 'turns',
    secure: m[1].endsWith('s'),
    host: m[2],
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

  const ev = new EventEmitter();
  const self = this;


  /* ====================== Context ====================== */

  let context = {

    // ── Identity & config ──
    mode:                 options.mode === 'lite' ? 'lite' : 'full',
    trickle:              options.trickle !== false,            // default true
    controlling:          options.controlling !== false,         // default true (offerer)
    iceServers:           options.iceServers || [],
    iceTransportPolicy:   options.iceTransportPolicy || 'all',   // 'all' | 'relay'
    includeLoopback:      !!options.includeLoopback,
    ipv6:                 options.ipv6 !== false,                // default true
    portRange:            options.portRange || [0, 0],           // [min, max]; 0 = any
    components:           options.components || 1,
    tieBreaker:           crypto.randomBytes(8),

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
    externalSocket:       null,  // externally-provided socket (useSocket)

    // ── TURN clients (for relay candidates) ──
    turnClients:          {},    // key 'host:port' → turn Socket
    turnPermissions:      {},    // key 'turnKey|peerIp' → { expires, timer }

    // ── STUN transactions ──
    pendingTransactions:  {},    // txnIdHex → { kind: 'check'|'consent'|'gather-srflx', pair?, timer?, callback }

    // ── Timers (bookkeeping — handles, not "state" that triggers cascades) ──
    checkTimer:           null,
    nominationTimer:      null,
    consentTimer:         null,

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
        context.controlling = !!opts.controlling;
        has_changed = true;
        // Role change → recompute pair priorities + re-sort
        recomputePairPriorities();
        ev.emit('rolechange', context.controlling ? 'controlling' : 'controlled');
      }
    }


    /* Credentials */

    if ('localUfrag' in opts) {
      if (opts.localUfrag !== context.localUfrag && opts.localUfrag) {
        context.localUfrag = opts.localUfrag;
        has_changed = true;
      }
    }

    if ('localPwd' in opts) {
      if (opts.localPwd !== context.localPwd && opts.localPwd) {
        context.localPwd = opts.localPwd;
        has_changed = true;
      }
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
          ev.emit('candidate', cand);
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
      } else if (cand && !findRemoteCandidate(cand.ip, cand.port)) {
        context.remoteCandidates.push(cand);
        has_changed = true;
        formPairsForNewRemote(cand);
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
        for (let i = 0; i < batch.length; i++) ev.emit('candidate', batch[i]);
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


    /* 2.5 — Auto-select: pick the highest-priority nominated-and-valid pair */
    if (!context.selectedPair && !context.closed) {
      let best = null;
      for (let i = 0; i < context.validList.length; i++) {
        const p = context.validList[i];
        if (!p.valid || !p.nominated) continue;
        if (!best || p.priority > best.priority) best = p;
      }
      if (best) {
        params_to_set.selectedPair = best;
        // ICE restart complete — drop the previous pair; new selectedPair
        // (assigned by the recursive set_context call) takes over send().
        if (context._previousPair) {
          context._previousPair = null;
        }
      }
    }


    /* 2.6 — Once selected, transition state to 'connected' */
    if (context.selectedPair &&
        context.state !== 'connected' &&
        context.state !== 'failed' &&
        context.state !== 'closed') {
      params_to_set.state = 'connected';
    }


    /* 2.7 — Once selected, stop check scheduler + drain triggered queue */
    if (context.selectedPair) {
      if (context.checkTimer) {
        clearInterval(context.checkTimer);
        context.checkTimer = null;
      }
      if (context.triggeredQueue && context.triggeredQueue.length > 0) {
        context.triggeredQueue.length = 0;
      }
    }


    /* 2.8 — Once selected, start consent freshness (RFC 7675) */
    if (context.selectedPair &&
        !context.consentTimer &&
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

    // Classify iceServers
    const stunServers = [];
    const turnServers = [];
    for (let i = 0; i < context.iceServers.length; i++) {
      const srv = context.iceServers[i];
      const urls = srv.urls || srv.url;
      const urlList = Array.isArray(urls) ? urls : [urls];
      for (let j = 0; j < urlList.length; j++) {
        const p = parseIceServerUri(urlList[j]);
        if (!p) continue;
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
    if (context._gathering_srflx > 0) return;
    if (context._gathering_relay > 0) return;
    set_context({ gatheringState: 'complete' });
  }


  /* ── Host candidate gathering ── */

  function gatherHostCandidates(done) {
    // If external socket is provided, use it directly as the only host.
    if (context.externalSocket) {
      const addr = context.externalSocket.address();
      addHostFromBoundSocket(context.externalSocket, addr);
      done();
      return;
    }

    const ifaces = os.networkInterfaces();
    const names = Object.keys(ifaces);
    const addrs = [];
    for (let i = 0; i < names.length; i++) {
      const list = ifaces[names[i]];
      for (let j = 0; j < list.length; j++) {
        const a = list[j];
        // Skip internal unless explicitly requested
        if (a.internal && !context.includeLoopback) continue;
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

    set_context({ add_local_candidate: cand });
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
        ev.emit('error', err);
      });

      sock.on('listening', function() {
        // success
      });

      sock.bind({ address: ip, port: 0, exclusive: false }, function() {
        let bound;
        try { bound = sock.address(); } catch (e) { cb(null, null); return; }
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
        ev.emit('candidateerror', { type: 'srflx', server: server.uri, base: baseAddr.address, error: err });
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
        const out = Buffer.isBuffer(u) ? u : Buffer.from(u.buffer, u.byteOffset, u.byteLength);
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
    const baseAddr = context.primarySocket.address();

    let finished = false;
    function finish(err, relayInfo, turnSocket) {
      if (finished) return;
      finished = true;
      if (timer) { clearTimeout(timer); context._gather_timers.delete(timer); }
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
        ev.emit('candidateerror', { type: 'relay', server: server.uri, error: err });
      }
      done();
    }

    // Use the Socket client from ./socket.js to allocate (lazy import)
    let turnSocket;
    import('./socket.js').then(function(mod) {
      if (context.closed) { finish(new Error('agent closed')); return; }
      try {
        const Socket = mod.default || mod.Socket;
        const parsed = server.parsed;

        // Map ICE-URI transport → Socket.transportType.
        //   turn:?transport=udp   → 'udp'
        //   turn:?transport=tcp   → 'tcp'
        //   turns:...             → 'tls'   (TLS over TCP)
        // Note: turns:?transport=udp would mean DTLS, which the Socket client
        // doesn't currently support — we fall back to 'tls' for safety.
        const transportType = parsed.secure ? 'tls' : (parsed.transport || 'udp');

        turnSocket = new Socket({
          isServer:      false,
          server:        parsed.host,
          port:          parsed.port || (parsed.secure ? 5349 : 3478),
          transportType: transportType,
          username:      server.username   || null,
          password:      server.credential || null,
          authMech:      (server.username && server.credential) ? 'long-term' : 'none',
          rto:           500,
          // TLS options — only used when transportType === 'tls'
          servername:         server.servername         || parsed.host,
          rejectUnauthorized: server.rejectUnauthorized,  // undefined → default (true)
          ca:                 server.ca || null,
        });
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
    const msg = wire.decode_message(buf);
    if (!msg) return;
    const txHex = txIdHex(msg.transactionId);

    // 1. Pending transaction (our outgoing STUN req — connectivity check, gather, etc.)
    const pending = context.pendingTransactions[txHex];
    if (pending) {
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
      for (let i = 0; i < context.checkList.length; i++) {
        if (context.checkList[i].state === 'waiting') { next = context.checkList[i]; break; }
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
        const anyValid = context.checkList.some((p) => p.valid);
        if (!anyValid) {
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
      // 487 role conflict → switch role, re-queue check
      if (msg) {
        const ec = msg.getAttribute(wire.ATTR.ERROR_CODE);
        if (ec && ec.code === 487) {
          handleRoleConflictFromResponse(pair);
          return;
        }
      }
      pair.state = 'failed';
      set_context({ pair_failed: pair });
      return;
    }

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
    // Triggered by cascade 2.8: selectedPair set, not lite, no timer yet.
    if (context.consentTimer) return;
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
    if (age >= CONSENT_FAILED_MS) {
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
    const timer = setTimeout(function() {
      const p = context.pendingTransactions[txHex];
      if (!p) return;
      delete context.pendingTransactions[txHex];
      if (p.callback) p.callback(null, null, new Error('consent timeout'));
    }, 10_000);
    if (timer.unref) timer.unref();

    context.pendingTransactions[txHex] = {
      kind: 'consent',
      pair: pair,
      timer: timer,
      callback: function(_msg, _rinfo, err) {
        delete context.pendingTransactions[txHex];
        if (timer) clearTimeout(timer);
        if (err) return;   // no response → leave lastSuccessAt stale
        // Successful response → feed back through set_context so cascades re-run.
        set_context({ consentLastSuccessAt: Date.now() });
      },
    };

    sendStunToRemote(pair.local, pair.remote, encoded.buf);
  }

  function handleBindingRequest(buf, msg, rinfo, sock, turnSocket) {
    if (context.closed) return;

    // Verify USERNAME and MESSAGE-INTEGRITY with OUR password (RFC 8445 §7.3)
    if (!context.localPwd) {
      // Not configured yet — silently drop
      return;
    }
    const validated = wire.validateStunMessage(buf, context.localPwd);
    if (!validated) {
      sendBindingError(msg, rinfo, sock, turnSocket, 401, 'Unauthenticated');
      return;
    }

    // USERNAME must be "<our-ufrag>:<their-ufrag>"
    const usernameAttr = msg.getAttribute(wire.ATTR.USERNAME);
    if (typeof usernameAttr !== 'string' || usernameAttr.indexOf(':') < 0) {
      sendBindingError(msg, rinfo, sock, turnSocket, 400, 'Bad Request');
      return;
    }
    const colonIdx = usernameAttr.indexOf(':');
    const usernameLocal = usernameAttr.substring(0, colonIdx);
    if (usernameLocal !== context.localUfrag) {
      // Wrong local ufrag — probably a stale packet
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
        sendBindingError(msg, rinfo, sock, turnSocket, 487, 'Role Conflict');
        return;
      }
      // We lose — switch to controlled
      switchRole(false);
    } else if (!context.controlling && icControlled !== null) {
      // Both claim controlled
      if (compareTieBreakers(context.tieBreaker, icControlled.raw) >= 0) {
        sendBindingError(msg, rinfo, sock, turnSocket, 487, 'Role Conflict');
        return;
      }
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

    // Always respond — even before processing, the peer needs a Success
    sendBindingSuccess(msg, rinfo, sock, turnSocket);

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
      const out = Buffer.isBuffer(buf) ? buf : Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
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
        const out = Buffer.isBuffer(buf) ? buf : Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
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
    if (context.nominationTimer) { clearTimeout(context.nominationTimer); context.nominationTimer = null; }

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

    // Close UDP sockets (but not external)
    const skeys = Object.keys(context.sockets);
    for (let i = 0; i < skeys.length; i++) {
      const s = context.sockets[skeys[i]];
      if (s !== context.externalSocket) {
        try { s.close(); } catch (e) {}
      }
    }
    context.sockets = {};
    context.primarySocket = null;
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
      if (cand) set_context({ add_remote_candidate: cand });
    },

    /** Convenience: just the local candidates. */
    get localCandidates()  { return context.localCandidates.slice(); },
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

    /** Provide an external socket to share instead of binding our own. */
    useSocket: function(sock) {
      set_context({ externalSocket: sock });
      if (sock) {
        try {
          const addr = sock.address();
          addHostFromBoundSocket(sock, { address: addr.address, port: addr.port, family: addr.family });
        } catch (e) {}
      }
    },

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
      const out = Buffer.isBuffer(buf) ? buf : Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
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
