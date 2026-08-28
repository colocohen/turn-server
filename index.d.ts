// Type definitions for turn-server
// STUN/TURN server + client + ICE agent for Node.js
// Project: https://github.com/colocohen/turn-server

/// <reference types="node" />

export type Bytes = Buffer | Uint8Array;
export type PemSource = string | Buffer;
export type Transport = 'udp' | 'tcp' | 'tls' | 'ws' | 'wss' | 'dtls';

/** A network address as used throughout the API. `family` is 1 (IPv4) or 2 (IPv6). */
export interface Address {
  ip: string;
  port: number;
  family?: number;
}

/** Result of parsing a STUN/TURN URI (e.g. `turns:host:5349?transport=tcp`). */
export interface ParsedUri {
  host: string;
  port: number;
  transport: Transport;
  secure: boolean;
  isTurn: boolean;
  isWs?: boolean;
  [key: string]: unknown;
}

// ─────────────────────────────────────────────────────────────────────────
//  Shared TLS / DTLS material
// ─────────────────────────────────────────────────────────────────────────

export type SNICallback = (
  servername: string,
  cb: (err: Error | null, context?: unknown) => void
) => void;

/** TLS material inherited by every `tls` and `dtls` endpoint (endpoint config wins). */
export interface TlsDefaults {
  cert?: PemSource;
  key?: PemSource;
  ca?: PemSource;
  SNICallback?: SNICallback;
}

/** Shared-socket DTLS config (RFC 7350 over the external UDP socket). */
export interface SharedDtlsOptions {
  cert?: PemSource;
  key?: PemSource;
  ca?: PemSource;
  SNICallback?: SNICallback;
  requestCert?: boolean;
  alpnProtocols?: string[];
  minVersion?: string;
  maxVersion?: string;
  mtu?: number;
  useCookies?: boolean;
  /** Inject lemon-tls's DTLSSession (otherwise lazy-imported). */
  DTLSSession?: unknown;
  lemonTls?: unknown;
}

// ─────────────────────────────────────────────────────────────────────────
//  Server
// ─────────────────────────────────────────────────────────────────────────

export interface AuthOptions {
  /** 'none' | 'short-term' | 'long-term' | 'oauth' */
  mechanism?: 'none' | 'short-term' | 'long-term' | 'oauth';
  realm?: string;
  /** username → password map for static credentials. */
  credentials?: Record<string, string>;
  /** Shared secret for REST API (ephemeral) credentials. */
  secret?: string;
}

export interface RelayOptions {
  ip?: string;
  externalIp?: string;
  portRange?: [number, number];
}

export interface ServerOptions {
  software?: string;
  auth?: AuthOptions;
  relay?: RelayOptions;

  // Convenience limits
  maxConnections?: number;
  userQuota?: number;
  totalQuota?: number;
  maxDataSize?: number;
  maxPermissionsPerAllocation?: number;
  maxChannelsPerAllocation?: number;
  idleTimeout?: number;
  /**
   * How long (ms) a hook may defer its decision before the server gives up and
   * **denies** the request. Default 5000. Applies to every hook that takes a
   * `HookCallback`; the relay hot-path hooks are synchronous and unaffected.
   */
  hookTimeout?: number;

  // Security
  allowLoopback?: boolean;
  checkOriginConsistency?: boolean;

  // TLS/DTLS
  tls?: TlsDefaults;
  /** Enable DTLS-to-server on the external socket (RFC 7350 + RFC 7983 demux). */
  dtls?: SharedDtlsOptions;
  sniCallback?: SNICallback;
  SNICallback?: SNICallback;

  // External (shared) UDP socket mode — feed packets via handlePacket().
  socket?: import('node:dgram').Socket;
  socket6?: import('node:dgram').Socket;

  // Dependency injection (optional; otherwise lazy-imported)
  createDTLSServer?: unknown;
  lemonTls?: unknown;
  WebSocketServer?: unknown;
  wsServer?: unknown;

  // Callbacks
  realmCallback?: (...args: unknown[]) => void;
  relayCallback?: (...args: unknown[]) => void;

  listen?: ListenEntry[];
}

export interface ListenEntry {
  port: number;
  transport: Transport;
  address?: string;
  cert?: PemSource;
  key?: PemSource;
  ca?: PemSource;
  SNICallback?: SNICallback;
  ALPNProtocols?: string[];
  requestCert?: boolean;
  minVersion?: string;
  maxVersion?: string;
  mtu?: number;
  [key: string]: unknown;
}

export interface ServerStats {
  activeConnections: number;
  activeAllocations: number;
  totalAllocations: number;
  authFailures: number;
  packetsRelayed: number;
  bytesRelayed: number;
  [key: string]: number;
}

export interface RelayInfo {
  direction: 'inbound' | 'outbound';
  peer: Address;
  source: Address | null;
  username: string | null;
  size: number;
  channel: number | null;
}

// ─────────────────────────────────────────────────────────────────────────
//  Hooks
// ─────────────────────────────────────────────────────────────────────────

/**
 * Decision callback for every hook except the two relay hot-path hooks.
 *
 * May be called **synchronously or asynchronously** — nothing is sent and no
 * state changes until it fires, so a database or Redis lookup inside the
 * listener is safe. Only the first call counts.
 *
 *   cb(true)                        allow
 *   cb(false)                       deny with the hook's default error code
 *   cb(false, 486)                  deny with a specific code
 *   cb(false, 508, 'No capacity')   deny with a code and a reason phrase
 *
 * `code` and `reason` are ignored by hooks whose rejection is a silent drop
 * (`accept`, `beforeBindingResponse`), since those never send a response.
 *
 * A listener that never calls `cb` is **denied** once `hookTimeout` elapses.
 */
export type HookCallback = (allowed: boolean, code?: number, reason?: string) => void;

/**
 * Decision callback for the relay hot path (`beforeRelay`, `beforeData`).
 *
 * These run once per relayed packet, so they are **synchronous**: the listener
 * must call `cb` in the same tick. A deferred answer is ignored and the packet
 * is dropped. Keep the check in memory (a local token bucket, a `Map`); never
 * await I/O here. Rejection is a silent drop, so there is no error code.
 */
export type SyncHookCallback = (allowed: boolean) => void;

/** `accept` — a new connection or UDP 5-tuple. */
export interface AcceptInfo {
  source: Address;
  transport: Transport;
}

/** `beforeBindingResponse` — before answering a STUN Binding request. */
export interface BindingResponseInfo {
  source: Address;
  transport: Transport | null;
}

/** `authorize` — an authenticated request, before the method runs. */
export interface AuthorizeInfo {
  method: number;
  methodName: string | null;
  username: string | null;
  source: Address | null;
}

/** `beforeAllocate` — an Allocate request. `lifetime` is writable. */
export interface AllocateInfo {
  username: string | null;
  source: Address | null;
  transport: number;
  /** Writable: assign to grant a different lifetime than the client asked for. */
  lifetime: number;
  requestedFamily: number | null;
  evenPort: unknown;
  reservationToken: Bytes | null;
  dontFragment: boolean;
}

/** `beforeRefresh` — a Refresh request. `lifetime` is writable. */
export interface RefreshInfo {
  username: string | null;
  source: Address | null;
  /** Writable: assign to grant a different lifetime. */
  lifetime: number;
  currentLifetime: number;
}

/** `beforePermission` — fires once per peer in a CreatePermission request. */
export interface PermissionInfo {
  username: string | null;
  source: Address | null;
  peer: Address;
}

/** `beforeChannelBind` — a ChannelBind request. */
export interface ChannelBindInfo {
  username: string | null;
  source: Address | null;
  channel: number;
  peer: Address;
}

/** `beforeConnect` — a Connect request (TCP relay, RFC 6062). */
export interface ConnectInfo {
  username: string | null;
  source: Address | null;
  peer: Address;
}

/** `beforeData` — inbound relay packet (peer → client). Hot path. */
export interface DataInfo {
  peer: Address;
  source: Address | null;
  username: string | null;
  size: number;
  direction: 'inbound';
}

/** `auth:failure` — a real authentication failure, not the normal 401 challenge. */
export interface AuthFailureInfo {
  username: string | null;
  code: number;
  reason: 'bad-integrity' | 'unknown-user' | 'wrong-credentials'
        | 'algorithm-mismatch' | 'invalid-token' | 'missing-credentials';
}

export interface Server {
  /** Raw internal context — advanced use only. */
  readonly context: Record<string, unknown>;

  on(event: 'listening', listener: (info: { transport: Transport; address: string; port: number }) => void): this;
  on(event: 'connection', listener: (socket: Socket) => void): this;
  on(event: 'authenticate', listener: (username: string, realm: string | null, cb: (key: Bytes | string | null) => void) => void): this;
  on(event: 'authenticate_oauth', listener: (token: Bytes, realm: string | null, cb: (err: Error | null, key?: Bytes | null) => void) => void): this;

  // ── Hooks: cb may fire synchronously or asynchronously ──
  on(event: 'accept', listener: (info: AcceptInfo, cb: HookCallback) => void): this;
  on(event: 'beforeBindingResponse', listener: (info: BindingResponseInfo, cb: HookCallback) => void): this;
  on(event: 'authorize', listener: (info: AuthorizeInfo, cb: HookCallback) => void): this;
  on(event: 'quota', listener: (username: string | null, cb: HookCallback) => void): this;
  on(event: 'beforeAllocate', listener: (info: AllocateInfo, cb: HookCallback) => void): this;
  on(event: 'beforeRefresh', listener: (info: RefreshInfo, cb: HookCallback) => void): this;
  on(event: 'beforePermission', listener: (info: PermissionInfo, cb: HookCallback) => void): this;
  on(event: 'beforeChannelBind', listener: (info: ChannelBindInfo, cb: HookCallback) => void): this;
  on(event: 'beforeConnect', listener: (info: ConnectInfo, cb: HookCallback) => void): this;

  // ── Hooks: relay hot path, cb MUST fire synchronously ──
  on(event: 'beforeRelay', listener: (info: RelayInfo, cb: SyncHookCallback) => void): this;
  on(event: 'beforeData', listener: (info: DataInfo, cb: SyncHookCallback) => void): this;

  on(event: 'onRelayed', listener: (socket: Socket, info: RelayInfo) => void): this;
  on(event: 'auth:failure', listener: (socket: Socket, info: AuthFailureInfo) => void): this;
  on(event: 'allocate', listener: (socket: Socket, allocation: Allocation) => void): this;
  on(event: 'allocate:expired', listener: (socket: Socket, allocation: Allocation) => void): this;
  on(event: 'error', listener: (err: Error) => void): this;
  on(event: 'close', listener: () => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
  off(event: string, listener: (...args: any[]) => void): this;

  start(): void;
  listen(config?: ListenEntry[], cb?: () => void): void;
  stop(cb?: () => void): void;
  drain(timeout?: number, cb?: () => void): void;
  drain(cb: () => void): void;

  addUser(username: string, password: string): void;
  removeUser(username: string): void;

  getClientCount(): number;
  getClients(): Record<string, Socket>;
  getStats(): ServerStats;
  isHealthy(): boolean;
  isDraining(): boolean;

  /** External-socket mode: feed an incoming UDP packet. */
  handlePacket(msg: Bytes, rinfo: { address: string; port: number; family?: string; size?: number }): void;
  /** External-socket mode: is this 5-tuple an active TURN/DTLS client? */
  hasClient(rinfo: { address: string; port: number; family?: string }): boolean;
  /** Bridge a WebSocket from any `ws`-compatible library into the server. */
  handleWebSocket(ws: unknown, req?: unknown): void;
}

export interface ServerConstructor {
  new (options?: ServerOptions): Server;
  (options?: ServerOptions): Server;
}

export const Server: ServerConstructor;
export function createServer(options?: ServerOptions): Server;

// ─────────────────────────────────────────────────────────────────────────
//  Allocation / Session
// ─────────────────────────────────────────────────────────────────────────

export interface Allocation {
  relayAddress: Address;
  lifetime: number;
  expiresAt: number;
  transport: number;
  username: string | null;
  permissions: Record<string, number>;
  channels: Record<string, unknown>;
  [key: string]: unknown;
}

/** Per-allocation traffic counters, as returned by `session.getBandwidth()`. */
export interface Bandwidth {
  /** Bytes relayed peer → client. */
  bytesIn: number;
  /** Bytes relayed client → peer. */
  bytesOut: number;
  /** Packets relayed peer → client. */
  packetsIn: number;
  /** Packets relayed client → peer (Send indications and ChannelData). */
  packetsOut: number;
}

export interface Session {
  readonly context: Record<string, unknown>;
  readonly isServer: boolean;
  on(event: 'auth:failure', listener: (info: AuthFailureInfo) => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
  off(event: string, listener: (...args: any[]) => void): this;
  message(buf: Bytes): void;
  getAllocation(): Allocation | null;
  /**
   * Live byte and packet counters for this allocation. Packet counts matter
   * independently of bytes: 1 MB in one packet and 1 MB in 10,000 packets cost
   * very different amounts of CPU, and the latter is a flood signature.
   */
  getBandwidth(): Bandwidth;
  enableAutoRefresh(): void;
  [key: string]: unknown;
}

export interface SessionConstructor {
  new (options?: Record<string, unknown>): Session;
  (options?: Record<string, unknown>): Session;
}
export const Session: SessionConstructor;

// ─────────────────────────────────────────────────────────────────────────
//  Socket (client + server-side per-connection transport)
// ─────────────────────────────────────────────────────────────────────────

export interface SocketOptions {
  isServer?: boolean;
  server?: string;
  port?: number;
  transportType?: Transport;
  username?: string | null;
  password?: string | null;
  authMech?: AuthOptions['mechanism'];
  software?: string | null;
  /** STUN retransmission base (ms) for UDP/DTLS; null/omit for reliable transports. */
  rto?: number | null;
  tcpTimeout?: number;
  /** See `ServerOptions.hookTimeout`. Default 5000 ms. */
  hookTimeout?: number;

  // TLS/DTLS client options
  servername?: string;
  ca?: PemSource | null;
  rejectUnauthorized?: boolean;
  alpnProtocols?: string[] | null;
  minVersion?: string | null;
  maxVersion?: string | null;
  mtu?: number | null;

  // WebSocket client options
  WebSocket?: unknown;
  wsPath?: string | null;
  wsUrl?: string | null;

  // DTLS injection (otherwise lazy-imported)
  connectDTLS?: unknown;
  lemonTls?: unknown;

  /** Server-side: function used to send bytes back to the peer. */
  send?: (buf: Bytes, port?: number, ip?: string) => void;
}

export interface AttributeInput {
  type: number;
  value?: unknown;
  raw?: Bytes;
}

export interface Socket {
  readonly context: Record<string, unknown>;
  readonly isServer: boolean;

  on(event: 'binding:success', listener: (msg: any) => void): this;
  on(event: 'binding:error', listener: (msg: any, err: any) => void): this;
  on(event: 'allocate:success', listener: (msg: any) => void): this;
  on(event: 'allocate:error', listener: (msg: any, err: any) => void): this;
  on(event: 'timeout', listener: () => void): this;
  on(event: 'onRelayed', listener: (info: RelayInfo) => void): this;
  on(event: 'error', listener: (err: Error) => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
  off(event: string, listener: (...args: any[]) => void): this;

  /** Feed raw inbound bytes (server-side transports drive the session this way). */
  feed(buf: Bytes): void;
  connect(cb?: () => void): void;
  close(): void;
  getSession(): Session;

  addUser(username: string, password: string): void;
  removeUser(username: string): void;
  set_context(patch: Record<string, unknown>): void;

  hasPermission(ip: string): boolean;
  getPeerByChannel(channel: number): Address | null;
  getChannelByPeer(ip: string, port: number): number | null;
  getAllocation(): Allocation | null;
  getRelayAddress(): Address | null;

  // Client request methods
  binding(attributes?: AttributeInput[]): void;
  allocate(options?: { lifetime?: number; transport?: number; [key: string]: unknown }): void;
  refresh(options?: { lifetime?: number }): void;
  createPermission(peers: Address | Address[]): void;
  channelBind(channel: number, peer: Address): void;
  /** Send application data to a peer (via Send indication or a bound channel). */
  send(peer: Address, data: Bytes, channel?: number | null): void;
}

export interface SocketConstructor {
  new (options?: SocketOptions): Socket;
  (options?: SocketOptions): Socket;
}
export const Socket: SocketConstructor;

// ─────────────────────────────────────────────────────────────────────────
//  Top-level client helpers
// ─────────────────────────────────────────────────────────────────────────

export interface ConnectOptions {
  username?: string;
  password?: string;
  software?: string;
  transport?: Transport;
  rto?: number;
  timeout?: number;
  autoRefresh?: boolean;

  // TLS/DTLS
  servername?: string;
  ca?: PemSource;
  rejectUnauthorized?: boolean;
  alpnProtocols?: string[];
  minVersion?: string;
  maxVersion?: string;
  mtu?: number;

  // WebSocket
  WebSocket?: unknown;
  wsPath?: string;
  wsUrl?: string;

  // DTLS injection
  connectDTLS?: unknown;
  lemonTls?: unknown;
}

/**
 * Connect to a STUN/TURN server. Returns the Socket immediately; the optional
 * callback fires once connected.
 */
export function connect(uri: string | ParsedUri, options: ConnectOptions, cb?: (err: Error | null, socket: Socket) => void): Socket;
export function connect(uri: string | ParsedUri, cb: (err: Error | null, socket: Socket) => void): Socket;
export function connect(uri: string | ParsedUri, options?: ConnectOptions): Socket;

/** Discover the public (server-reflexive) address via a STUN Binding request. */
export function getPublicIP(server: string, options: { timeout?: number }, cb: (err: Error | null, address: Address | null) => void): Socket;
export function getPublicIP(server: string, cb: (err: Error | null, address: Address | null) => void): Socket;
export function getPublicIP(cb: (err: Error | null, address: Address | null) => void): Socket;

export interface NatResult {
  mappedAddress: Address | null;
  otherAddress: Address | null;
  /** e.g. 'full-cone' | 'restricted-cone' | 'symmetric-or-port-restricted' | 'blocked' | 'unknown' | 'timeout' */
  type: string;
}

/** Best-effort NAT type detection (RFC 5780). Requires a STUN server with OTHER-ADDRESS. */
export function detectNAT(server: string, options: { timeout?: number }, cb: (err: Error | null, result: NatResult) => void): Socket;
export function detectNAT(server: string, cb: (err: Error | null, result: NatResult) => void): Socket;

/** Resolve a URI (DNS SRV + A/AAAA) into a concrete host/port. */
export function resolve(uri: string, cb: (err: Error | null, parsed?: ParsedUri) => void): void;

// ─────────────────────────────────────────────────────────────────────────
//  ICE agent (RFC 8445)
// ─────────────────────────────────────────────────────────────────────────

export interface IceServerConfig {
  urls: string | string[];
  username?: string;
  credential?: string;
  [key: string]: unknown;
}

export interface IceAgentOptions {
  /** 'full' (default) or 'lite'. */
  mode?: 'full' | 'lite';
  iceServers?: IceServerConfig[];
  controlling?: boolean;
  components?: number;
  localUfrag?: string;
  localPwd?: string;
  [key: string]: unknown;
}

export interface IceParameters {
  ufrag: string;
  pwd: string;
  iceLite?: boolean;
}

export interface IceCandidate {
  foundation: string;
  component: number;
  protocol: string;
  priority: number;
  ip: string;
  port: number;
  type: 'host' | 'srflx' | 'prflx' | 'relay';
  [key: string]: unknown;
}

export interface IceAgent {
  readonly context: Record<string, unknown>;
  readonly localParameters: IceParameters;
  readonly remoteParameters: IceParameters | null;

  on(event: 'candidate', listener: (candidate: IceCandidate) => void): this;
  on(event: 'candidateerror', listener: (err: { type: string; error?: Error }) => void): this;
  on(event: 'statechange', listener: (state: string) => void): this;
  on(event: 'selectedpair', listener: (pair: unknown) => void): this;
  on(event: 'data', listener: (buf: Buffer) => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
  off(event: string, listener: (...args: any[]) => void): this;
  once(event: string, listener: (...args: any[]) => void): this;

  setLocalParameters(params: IceParameters): void;
  setRemoteParameters(params: IceParameters): void;
  addRemoteCandidate(candidate: IceCandidate | string): void;
  gather(): void;
  useSocket(sock: unknown): void;
  send(buf: Bytes): void;
  restart(): void;
  close(): void;
  set_context(patch: Record<string, unknown>): void;
}

export interface IceAgentConstructor {
  new (options?: IceAgentOptions): IceAgent;
}
export const IceAgent: IceAgentConstructor;

// ─────────────────────────────────────────────────────────────────────────
//  Candidate helpers (RFC 8445 §5.1)
// ─────────────────────────────────────────────────────────────────────────

export namespace candidate {
  function computeCandidatePriority(type: string, localPreference?: number, componentId?: number): number;
  function computePairPriority(controllingPriority: number, controlledPriority: number, controlling: boolean): number;
  function computeFoundation(...args: unknown[]): string;
  const _: unknown;
}

// ─────────────────────────────────────────────────────────────────────────
//  Wire protocol (binary codec, RFC 5389 / 8489 / 8656)
// ─────────────────────────────────────────────────────────────────────────

export namespace wire {
  const ATTR: Record<string, number>;
  const METHOD: Record<string, number>;
  const CLASS: Record<string, number>;
  const TRANSPORT: { UDP: number; TCP: number };
  const FAMILY: { IPV4: number; IPV6: number };
  const METHOD_NAME: Record<number, string>;
  const CLASS_NAME: Record<number, string>;

  function parseUri(uri: string): ParsedUri | null;
  function encode_message(options: {
    method?: number; cls?: number; transactionId?: Bytes;
    attributes?: AttributeInput[]; key?: Bytes | null;
    fingerprint?: boolean; integrity?: 'sha1' | 'sha256' | 'sha384' | 'sha512';
  }): { buf: Uint8Array; [key: string]: unknown };

  function encode_channel_data(channel: number, data: Bytes): Uint8Array;
  function decode_channel_data(buf: Bytes): { channel: number; data: Uint8Array };
  function is_stun(buf: Bytes): boolean;
  function is_channel_data(buf: Bytes): boolean;
  function to_buffer(u: Bytes): Buffer;
  function stun_stream_frame_length(buf: Bytes, off: number, avail: number): number;
  function tcp_frame(data: Bytes): Uint8Array;

  function compute_long_term_key(username: string, realm: string, password: string): Buffer;
  function compute_short_term_key(password: string): Buffer;
  function compute_userhash(username: string, realm: string): Uint8Array;

  // Other exports are available at runtime.
  const _: unknown;
}

// ─────────────────────────────────────────────────────────────────────────
//  Default export (same surface as the named exports)
// ─────────────────────────────────────────────────────────────────────────

declare const _default: {
  createServer: typeof createServer;
  connect: typeof connect;
  getPublicIP: typeof getPublicIP;
  detectNAT: typeof detectNAT;
  resolve: typeof resolve;
  Server: ServerConstructor;
  Socket: SocketConstructor;
  Session: SessionConstructor;
  IceAgent: IceAgentConstructor;
  candidate: typeof candidate;
  wire: typeof wire;
};
export default _default;
