// src/ice_portmap.js
// Port-mapping ↔ ICE bridge — UPnP-IGD / NAT-PMP / PCP assisted gathering.
//
// The fourth way to obtain a candidate (RFC 8445 §5.1.1 explicitly allows
// candidates obtained "through other means"): ask the gateway to forward a
// port to one of our bound host sockets, and advertise the external
// address:port as a server-reflexive candidate. libnice has shipped the
// same idea (gupnp-igd) for years.
//
// Why it is often STRONGER than STUN srflx: a mapping is a real forwarding
// rule — inbound traffic from ANY peer reaches the socket — where a STUN
// srflx behind a symmetric NAT is per-destination and near-useless. For a
// P2P client this frequently yields a direct connection with no STUN and
// no TURN at all.
//
// Shape mirrors src/ice_mdns.js exactly:
//   - port-mapper is an optionalDependency, imported lazily on first use
//     (the lemon-tls / ws / mdns-local pattern); an { instance } or
//     { module } can be injected instead.
//   - ONE Mapper per address family per process, refcounted. Gateway
//     discovery costs seconds — it must happen once, not per agent.
//     mapper.start() is joinable (idempotent) so late agents just join.
//   - release() by the last agent closes mappers we created; injected
//     instances are never closed here.
//
// Policy enforced here (not in the agent, not in port-mapper):
//   - CGNAT / double-NAT gate: negotiation reports addressKind; anything
//     other than 'public' means the mapping cannot be reached from the
//     internet — the whole source is marked dead for this process and
//     every request fails fast with one clear error. (A gateway will
//     happily create the useless mapping if asked; we don't ask.)
//   - Gathering budget: mapPort() self-cancels after `timeout` ms using
//     the map handle's cancel() — without it, NAT-PMP's retransmission
//     schedule can hold a callback for over two minutes on a silent
//     gateway, wedging gathering completion.
//   - checkLocalPort is skipped per-call: the ICE agent maps sockets it
//     just bound; the "nothing is listening" advisory would cost a check
//     per candidate to warn about something impossible.

/* ====================== Shared state ====================== */

var shared = {
  module:   null,
  loading:  null,
  refs:     0,
  families: {
    ipv4: null,   // { mapper, owned, dead: Error|null }
    ipv6: null,
  },
};


function loadModule(injected, cb) {
  if (injected) return cb(null, injected);
  if (shared.module) return cb(null, shared.module);
  if (!shared.loading) {
    shared.loading = import('port-mapper').then(
      function(m) { shared.module = m; shared.loading = null; return m; },
      function(err) { shared.loading = null; throw err; }
    );
  }
  shared.loading.then(
    function(m) { cb(null, m); },
    function() {
      cb(new Error(
        'Port-mapping candidate support requires the optional dependency ' +
        '"port-mapper" (npm install port-mapper), or inject an instance ' +
        'via the agent\'s portMapping.instance option.'));
    }
  );
}


/* ====================== acquire / release ====================== */

/**
 * options:
 *   instance      injected Mapper (IPv4). Not owned; never closed here.
 *   instance6     injected Mapper for IPv6.
 *   module        injected port-mapper module (skip dynamic import)
 *   description   shown in the router UI (default 'webrtc ice'). Routers
 *                 display this to the user — identify your app.
 *   lifetime      lease seconds (default 3600; auto-renewed by port-mapper)
 *   timeout       per-mapping budget ms (default 3000) — covers waiting
 *                 for negotiation AND the map exchange; self-cancels after.
 *   mapperOptions extra createMapper options (gateway, interface,
 *                 protocols, searchTimeout, ...). negotiateTimeout and
 *                 searchTimeout get ICE-appropriate defaults (3000/2000)
 *                 unless overridden — the library defaults (10s/3s) are
 *                 tuned for "open a port for my app", not for a gathering
 *                 phase a human is waiting on.
 *
 * cb(err, handle) — handle: { mapPort, unmapPort, release }
 */
function acquire(options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  options = options || {};

  var description = options.description || 'webrtc ice';
  var lifetime    = options.lifetime    || 3600;
  var timeout     = options.timeout     || 3000;
  var released    = false;

  // Track which (family, internalPort, protocol) THIS handle mapped, so
  // release() only unmaps its own and never a sibling agent's.
  var ownMappings = [];

  shared.refs++;
  cb(null, {

    /**
     * Map internalPort/udp on the gateway for `family` ('IPv4'|'IPv6').
     * cb2(err, { externalIp, externalPort, via, lifetime })
     * Errors carry .code where known:
     *   'EPORTMAPCGNAT'   gateway's external address is not public —
     *                     source is dead for the whole process
     *   'EPORTMAPBUDGET'  budget elapsed (silent/slow gateway)
     */
    mapPort: function(internalPort, family, cb2) {
      if (released) return setImmediate(cb2, stateError());
      var famKey = (family === 'IPv6') ? 'ipv6' : 'ipv4';

      withFamily(famKey, options, function(err, entry) {
        if (released) return cb2(stateError());
        if (err) return cb2(err);
        if (entry.dead) return cb2(entry.dead);

        var settled = false;
        var handle = null;
        var timer = setTimeout(function() {
          if (settled) return;
          settled = true;
          var e = new Error(
            'port-mapping abandoned after ' + timeout + 'ms budget ' +
            '(gateway slow or silent; NAT-PMP retransmission alone can ' +
            'run minutes)');
          e.code = 'EPORTMAPBUDGET';
          if (handle && handle.cancel) {
            try { handle.cancel('ICE gathering budget elapsed'); } catch (_) {}
          }
          cb2(e);
        }, timeout);

        handle = entry.mapper.map({
          internalPort:   internalPort,
          externalPort:   internalPort,   // preference; gateway may substitute
          protocol:       'udp',
          lifetime:       lifetime,
          description:    description,
          checkLocalPort: false,          // we bound this socket ourselves
        }, function(err2, mapping) {
          if (settled) {
            // Budget already fired. If the mapping landed anyway, remove
            // it — nobody will advertise it, and an unowned forwarding
            // rule should not outlive its purpose.
            if (!err2 && mapping) {
              try {
                entry.mapper.unmap(
                  { internalPort: internalPort, protocol: 'udp' },
                  function() {});
              } catch (_) {}
            }
            return;
          }
          settled = true;
          clearTimeout(timer);
          if (err2) return cb2(err2);

          // Belt-and-braces: negotiation vets the gateway, but the
          // mapping's own address wins if they disagree (multi-WAN,
          // address change between start and map).
          if (mapping.addressKind && mapping.addressKind !== 'public') {
            var e = cgnatError(mapping.externalIp, mapping.addressKind);
            try {
              entry.mapper.unmap(
                { internalPort: internalPort, protocol: 'udp' },
                function() {});
            } catch (_) {}
            return cb2(e);
          }

          ownMappings.push({ family: famKey, internalPort: internalPort });
          cb2(null, {
            externalIp:   mapping.externalIp,
            externalPort: mapping.externalPort,
            via:          mapping.via,
            lifetime:     mapping.lifetime,
          });
        });
      });
    },

    /** Remove one of THIS handle's mappings (idempotent). */
    unmapPort: function(internalPort, family) {
      var famKey = (family === 'IPv6') ? 'ipv6' : 'ipv4';
      for (var i = ownMappings.length - 1; i >= 0; i--) {
        if (ownMappings[i].family === famKey &&
            ownMappings[i].internalPort === internalPort) {
          ownMappings.splice(i, 1);
        }
      }
      var entry = shared.families[famKey];
      if (!entry || !entry.mapper) return;
      try {
        entry.mapper.unmap({ internalPort: internalPort, protocol: 'udp' },
                           function() {});
      } catch (_) {}
    },

    /** Drop this agent's hold; last one out closes owned mappers. */
    release: function() {
      if (released) return;
      released = true;

      // Our own mappings go regardless of refcount — the candidates that
      // justified them die with the agent.
      for (var i = 0; i < ownMappings.length; i++) {
        var m = ownMappings[i];
        var entry = shared.families[m.family];
        if (entry && entry.mapper) {
          try {
            entry.mapper.unmap({ internalPort: m.internalPort, protocol: 'udp' },
                               function() {});
          } catch (_) {}
        }
      }
      ownMappings = [];

      shared.refs--;
      if (shared.refs > 0) return;

      var fams = ['ipv4', 'ipv6'];
      for (var f = 0; f < fams.length; f++) {
        var e = shared.families[fams[f]];
        shared.families[fams[f]] = null;
        if (e && e.mapper && e.owned) {
          // close() unmaps whatever is left, then shuts down.
          try { e.mapper.close(function() {}); } catch (_) {}
        }
      }
    },
  });
}


/* ====================== Per-family mapper ====================== */

function withFamily(famKey, options, cb) {
  var entry = shared.families[famKey];
  if (entry) {
    // mapper.start() joins in-flight negotiation and replays a settled
    // one — the sequencing problem is solved in port-mapper itself.
    return entry.mapper.start(function(err, info) {
      afterStart(entry, err, info, cb);
    });
  }

  var injected = (famKey === 'ipv6') ? options.instance6 : options.instance;
  if (injected) {
    entry = shared.families[famKey] = { mapper: injected, owned: false, dead: null };
    return entry.mapper.start(function(err, info) {
      afterStart(entry, err, info, cb);
    });
  }

  loadModule(options.module, function(err, mod) {
    if (err) return cb(err);
    // Raced another caller while the module loaded?
    if (shared.families[famKey]) return withFamily(famKey, options, cb);

    var createMapper = mod.createMapper ||
                       (mod.default && mod.default.createMapper);
    if (!createMapper) {
      return cb(new Error('port-mapper: createMapper export not found'));
    }

    var mapperOptions = Object.assign({
      negotiateTimeout: 3000,
      searchTimeout:    2000,
    }, options.mapperOptions || {}, {
      family:      famKey,
      description: options.description || 'webrtc ice',
    });

    var mapper;
    try {
      mapper = createMapper(mapperOptions);
    } catch (e) {
      // Typically: no interface in this family on this host.
      return cb(e);
    }

    entry = shared.families[famKey] = { mapper: mapper, owned: true, dead: null };
    entry.mapper.start(function(err2, info) {
      afterStart(entry, err2, info, cb);
    });
  });
}

function afterStart(entry, err, info, cb) {
  if (err) {
    // NoGatewayError etc. — the source is unusable this session. Cache the
    // verdict so every subsequent request fails fast instead of paying the
    // negotiation timeout again and again.
    entry.dead = err;
    return cb(err);
  }
  if (info && info.addressKind && info.addressKind !== 'public') {
    entry.dead = cgnatError(info.externalIp, info.addressKind);
    return cb(entry.dead);
  }
  cb(null, entry);
}

function cgnatError(ip, kind) {
  var e = new Error(
    'gateway external address ' + ip + ' is ' + kind + ', not public — ' +
    'a port mapping there cannot be reached from the internet ' +
    (kind === 'cgnat' ? '(carrier-grade NAT; ask the ISP for a public ' +
     'address, or rely on STUN/TURN)' : '(double NAT upstream)'));
  e.code = 'EPORTMAPCGNAT';
  return e;
}

function stateError() {
  var e = new Error('ice_portmap: handle released');
  e.code = 'EPORTMAPRELEASED';
  return e;
}


/* ====================== Exports ====================== */

export { acquire };
export default { acquire };
