// src/ice_mdns.js
// mDNS ↔ ICE bridge — draft-ietf-mmusic-mdns-ice-candidates.
//
// This module owns everything the ICE agent needs to know about mDNS,
// so ice_agent.js never touches mdns-local directly and mdns-local never
// learns anything about ICE. Two directions:
//
//   resolve(name, cb)  — inbound:  a peer sent a ".local" candidate;
//                        turn it into an IP under the draft's rules.
//   register(ip, cb)   — outbound: conceal one of OUR host addresses
//                        behind a fresh UUID ".local" name (client /
//                        Electron privacy mode; opt-in at the agent).
//
// ── Process-wide instance, refcounted ─────────────────────────────────
//
// Port 5353 is a per-process resource: an SFU with hundreds of IceAgents
// must NOT open hundreds of multicast sockets. acquire() hands every
// caller a handle onto ONE lazily created MDNS instance; release() drops
// the refcount and destroys the instance when the last agent lets go.
// The instance is created on first acquire — a server that never sees a
// .local candidate never binds 5353 at all.
//
// Sharing one instance also shares mdns-local's answer cache, so ten
// candidates from the same browser cost one multicast query total.
//
// ── Dependency shape ──────────────────────────────────────────────────
//
// mdns-local is an optionalDependency, imported lazily on first use —
// the same pattern as lemon-tls (DTLS) and ws (WebSocket server). Callers
// can also inject:
//   { instance }  — an MDNS instance the app already runs (we won't own
//                   or destroy it, and won't bind a second socket)
//   { module }    — the mdns-local module itself (bundlers / testing)
//
// ── Draft rules enforced here (not in the agent, not in mdns-local) ──
//
//   * Only strict UUID ".local" names are resolved
//     (isResolvableMdnsCandidate — hostile peers must not be able to aim
//     our connectivity checks at "printer.local").
//   * A resolution yielding more than one address is discarded
//     ("An ICE agent SHOULD ignore candidates where the hostname
//     resolution returns more than one IP address").
//   * One registered name per local address, reused across candidates
//     ("If there is already an mDNS hostname for that IP address,
//     the agent uses it").
//   * Registration skips the RFC 6762 probe (§3.1.1 permits this for
//     UUID names) so gathering pays ~0ms instead of ~750ms.

import crypto from 'node:crypto';
import { isResolvableMdnsCandidate } from './ice_candidate.js';

/* ====================== Shared instance state ====================== */

var shared = {
  instance: null,     // the MDNS instance in use
  owned: false,       // did WE create it (→ we destroy it at refs==0)?
  refs: 0,
  loading: null,      // in-flight import promise (dedup concurrent acquires)
  module: null,       // cached mdns-local module
};

// hostname → [cb, ...] — dedup concurrent resolves for the same name at
// this layer too. mdns-local also dedups internally, but this module must
// not assume the injected instance is a version that does.
var pendingResolves = Object.create(null);

// ip → { name, handle, refs } — outbound registrations, one per address.
var registrations = Object.create(null);


/* ====================== Module loading ====================== */

function loadModule(injected, cb) {
  if (injected) return cb(null, injected);
  if (shared.module) return cb(null, shared.module);
  if (!shared.loading) {
    shared.loading = import('mdns-local').then(
      function(m) { shared.module = m; shared.loading = null; return m; },
      function(err) { shared.loading = null; throw err; }
    );
  }
  shared.loading.then(
    function(m) { cb(null, m); },
    function() {
      cb(new Error(
        'mDNS candidate support requires the optional dependency ' +
        '"mdns-local" (npm install mdns-local), or inject an instance ' +
        'via the agent\'s mdns.instance option.'));
    }
  );
}


/* ====================== acquire / release ====================== */

/**
 * Acquire a handle on the process-wide mDNS instance.
 *
 * options:
 *   instance      injected MDNS instance (not owned; never destroyed here)
 *   module        injected mdns-local module (skip dynamic import)
 *   mdnsOptions   options for `new MDNS(...)` when WE create the instance
 *                 (e.g. { strictSourceCheck: false } for Docker/VPN LANs)
 *   timeout       per-resolve timeout ms (default 3000)
 *   unicast       set the QU bit on resolve queries (default false — see
 *                 mdns-local resolveHostname docs for the reuseAddr
 *                 sharing hazard; enable in single-daemon containers)
 *
 * cb(err, handle) — handle: { resolve, register, unregister, release }
 */
function acquire(options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  options = options || {};

  var timeout = options.timeout || 3000;
  var unicast = !!options.unicast;
  var released = false;

  function ready(err) {
    if (err) return cb(err);
    shared.refs++;
    cb(null, makeHandle());
  }

  if (options.instance) {
    // Injected instance wins — and if we previously created our own,
    // the injected one is used for THIS handle without disturbing it.
    if (!shared.instance) {
      shared.instance = options.instance;
      shared.owned = false;
    }
    return ready(null);
  }

  if (shared.instance) return ready(null);

  loadModule(options.module, function(err, mod) {
    if (err) return ready(err);
    if (shared.instance) return ready(null);   // raced another acquire
    var MDNS = mod.MDNS || (mod.default && mod.default.MDNS);
    if (!MDNS) return ready(new Error('mdns-local: MDNS export not found'));
    try {
      shared.instance = new MDNS(options.mdnsOptions || {});
      shared.owned = true;
    } catch (e) {
      return ready(e);
    }
    ready(null);
  });

  function makeHandle() {
    return {

      /**
       * Resolve an inbound ".local" candidate address to a single IP.
       * cb(err, ip) — errors:
       *   .code === 'EMDNSFORMAT'    not a strict UUID .local name
       *   .code === 'EMDNSAMBIGUOUS' resolved to more than one address
       *   (or the underlying timeout / network error)
       */
      resolve: function(hostname, cb2) {
        if (released) return setImmediate(cb2, stateError());
        if (!isResolvableMdnsCandidate(hostname)) {
          var fe = new Error(
            'mDNS candidate rejected: not a single UUID label + .local ' +
            '(draft-ietf-mmusic-mdns-ice-candidates §3.1/§3.2): ' + hostname);
          fe.code = 'EMDNSFORMAT';
          return setImmediate(cb2, fe);
        }

        if (pendingResolves[hostname]) {
          pendingResolves[hostname].push(cb2);
          return;
        }
        pendingResolves[hostname] = [cb2];

        shared.instance.resolveHostname(
          hostname,
          { timeout: timeout, unicast: unicast },
          function(err, addresses) {
            var waiters = pendingResolves[hostname] || [];
            delete pendingResolves[hostname];

            var out = null, ip = null;
            if (err) {
              out = err;
            } else if (!addresses || addresses.length === 0) {
              out = new Error('mDNS resolution returned no addresses: ' + hostname);
            } else if (addresses.length > 1) {
              out = new Error(
                'mDNS candidate rejected: resolved to multiple addresses ' +
                '(draft: SHOULD ignore): ' + hostname);
              out.code = 'EMDNSAMBIGUOUS';
            } else {
              ip = addresses[0];
            }
            for (var i = 0; i < waiters.length; i++) waiters[i](out, ip);
          }
        );
      },

      /**
       * Register (or reuse) a concealment name for one of OUR addresses.
       * cb(err, name) — name is 'xxxxxxxx-....local', announced already
       * (skipProbe: UUID collision probability is negligible; the draft
       * permits skipping, and conflict-rename stays active regardless).
       */
      register: function(ip, cb2) {
        if (released) return setImmediate(cb2, stateError());

        var existing = registrations[ip];
        if (existing) {
          existing.refs++;
          return setImmediate(cb2, null, existing.name);
        }

        var uuid = crypto.randomUUID();

        var entry = { name: uuid + '.local', handle: null, refs: 1 };
        registrations[ip] = entry;
        try {
          entry.handle = shared.instance.claimHost(uuid, {
            addresses: [ip],
            skipProbe: true,
          });
        } catch (e) {
          delete registrations[ip];
          return setImmediate(cb2, e);
        }
        setImmediate(cb2, null, entry.name);
      },

      /** Drop one reference to a registered address; goodbye at zero. */
      unregister: function(ip) {
        var entry = registrations[ip];
        if (!entry) return;
        entry.refs--;
        if (entry.refs > 0) return;
        delete registrations[ip];
        try { if (entry.handle) entry.handle.stop(); } catch (_) {}
      },

      /** Release this agent's hold on the shared instance. Idempotent. */
      release: function() {
        if (released) return;
        released = true;
        shared.refs--;
        if (shared.refs > 0) return;

        // Last agent out: clear registrations, flush pending, and destroy
        // the instance only if we created it. An injected instance belongs
        // to the application — we just forget our pointer to it.
        for (var ip in registrations) {
          try { if (registrations[ip].handle) registrations[ip].handle.stop(); } catch (_) {}
        }
        registrations = Object.create(null);

        for (var h in pendingResolves) {
          var ws = pendingResolves[h];
          for (var i = 0; i < ws.length; i++) setImmediate(ws[i], stateError());
        }
        pendingResolves = Object.create(null);

        var inst = shared.instance, owned = shared.owned;
        shared.instance = null;
        shared.owned = false;
        if (owned && inst) {
          try { inst.destroy(); } catch (_) {}
        }
      },
    };
  }
}

function stateError() {
  var e = new Error('ice_mdns: handle released');
  e.code = 'EMDNSRELEASED';
  return e;
}


/* ====================== Exports ====================== */

export { acquire };
export default { acquire };
