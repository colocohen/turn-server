import dns from 'node:dns';

import Session from './src/session.js';
import Socket from './src/socket.js';
import { Server, createServer } from './src/server.js';
import * as wire from './src/wire.js';
import { IceAgent } from './src/ice_agent.js';
import * as candidate from './src/ice_candidate.js';


/* ====================== TURN URI + DNS SRV ====================== */

function resolve(uri, cb) {
  var parsed = wire.parseUri(uri);
  if (!parsed) return cb(new Error('Invalid URI: ' + uri));

  if (/^\d+\.\d+\.\d+\.\d+$/.test(parsed.host) || parsed.host.indexOf(':') >= 0) {
    return cb(null, parsed);
  }

  var prefix = parsed.secure ? (parsed.isTurn ? '_turns' : '_stuns') : (parsed.isTurn ? '_turn' : '_stun');
  var proto = (parsed.transport === 'udp') ? '_udp' : '_tcp';
  var srvName = prefix + '.' + proto + '.' + parsed.host;

  dns.resolveSrv(srvName, function(err, records) {
    if (!err && records && records.length > 0) {
      records.sort(function(a, b) { return a.priority - b.priority || b.weight - a.weight; });
      parsed.host = records[0].name;
      parsed.port = records[0].port;
    }
    dns.lookup(parsed.host, function(err2, address) {
      if (!err2 && address) parsed.host = address;
      cb(null, parsed);
    });
  });
}


/* ====================== connect() ====================== */

function connect(uri, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  options = options || {};

  var parsed = typeof uri === 'string' ? wire.parseUri(uri) : uri;
  if (!parsed && typeof uri === 'string') {
    var parts = uri.split(':');
    parsed = { host: parts[0], port: parseInt(parts[1]) || 3478, transport: 'udp', secure: false, isTurn: true };
  }

  var socket = new Socket({
    isServer: false,
    server: parsed.host,
    port: parsed.port,
    transportType: parsed.transport || options.transport || 'udp',
    username: options.username || null,
    password: options.password || null,
    authMech: (options.username && options.password) ? 'long-term' : 'none',
    software: options.software || null,
    rto: (parsed.transport === 'udp') ? (options.rto || 500) : null,
    servername: options.servername || parsed.host,
    ca: options.ca || null,
    rejectUnauthorized: options.rejectUnauthorized,
  });

  if (options.autoRefresh !== false) {
    socket.getSession().enableAutoRefresh();
  }

  if (typeof uri === 'string' && !/^\d+\.\d+\.\d+\.\d+$/.test(parsed.host)) {
    resolve(uri, function(err, resolved) {
      if (resolved) {
        socket.context.serverHost = resolved.host;
        socket.context.serverPort = resolved.port;
      }
      socket.connect(function() { if (cb) cb(null, socket); });
    });
  } else {
    socket.connect(function() { if (cb) cb(null, socket); });
  }

  return socket;
}


/* ====================== getPublicIP() ====================== */

function getPublicIP(server, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  if (typeof server === 'function') { cb = server; server = 'stun:stun.l.google.com:19302'; options = {}; }
  options = options || {};

  var parsed = wire.parseUri(server) || { host: server, port: 3478, transport: 'udp' };
  var done = false;

  var socket = new Socket({
    isServer: false,
    server: parsed.host,
    port: parsed.port,
    transportType: parsed.transport || 'udp',
    rto: 500,
  });

  socket.on('binding:success', function(msg) {
    if (done) return; done = true;
    var mapped = msg.getAttribute(wire.ATTR.XOR_MAPPED_ADDRESS)
              || msg.getAttribute(wire.ATTR.MAPPED_ADDRESS);
    socket.close();
    cb(null, mapped ? { ip: mapped.ip, port: mapped.port, family: mapped.family } : null);
  });

  socket.on('binding:error', function(msg, err) {
    if (done) return; done = true;
    socket.close();
    cb(new Error('Binding error: ' + (err ? err.code : 'unknown')));
  });

  socket.on('timeout', function() {
    if (done) return; done = true;
    socket.close();
    cb(new Error('STUN timeout'));
  });

  socket.connect(function() { socket.binding(); });

  setTimeout(function() {
    if (done) return; done = true;
    socket.close();
    cb(new Error('STUN timeout'));
  }, options.timeout || 5000);

  return socket;
}


/* ====================== NAT type detection (RFC 5780) ====================== */

function detectNAT(server, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  options = options || {};

  var parsed = wire.parseUri(server) || { host: server, port: 3478, transport: 'udp' };
  var results = { mappedAddress: null, otherAddress: null, type: 'unknown' };
  var step = 0;
  var done = false;

  var socket = new Socket({
    isServer: false,
    server: parsed.host,
    port: parsed.port,
    transportType: 'udp',
    rto: 500,
  });

  function finish(type) {
    if (done) return; done = true;
    results.type = type;
    socket.close();
    cb(null, results);
  }

  socket.on('binding:success', function(msg) {
    var mapped = msg.getAttribute(wire.ATTR.XOR_MAPPED_ADDRESS);
    var other = msg.getAttribute(wire.ATTR.OTHER_ADDRESS);

    if (step === 0) {
      results.mappedAddress = mapped;
      results.otherAddress = other;
      if (!other) return finish('unknown (server lacks OTHER-ADDRESS)');
      // Test II: binding with CHANGE-REQUEST (change IP + port)
      step = 1;
      socket.binding([{ type: wire.ATTR.CHANGE_REQUEST, value: { changeIp: true, changePort: true } }]);
    } else if (step === 1) {
      finish('full-cone');
    } else if (step === 2) {
      finish('restricted-cone');
    }
  });

  socket.on('timeout', function() {
    if (step === 1) {
      // Test II timeout → Test III: change port only
      step = 2;
      socket.binding([{ type: wire.ATTR.CHANGE_REQUEST, value: { changeIp: false, changePort: true } }]);
    } else if (step === 2) {
      finish('symmetric-or-port-restricted');
    } else {
      finish('blocked');
    }
  });

  socket.connect(function() { socket.binding(); });

  setTimeout(function() { if (!done) finish('timeout'); }, options.timeout || 10000);

  return socket;
}


/* ====================== Exports ====================== */

export {
  Session, Socket, Server, createServer,
  connect, getPublicIP, detectNAT, resolve,
  wire,
  IceAgent, candidate,
};

export default {
  Session, Socket, Server, createServer,
  connect, getPublicIP, detectNAT, resolve,
  wire,
  IceAgent, candidate,
};