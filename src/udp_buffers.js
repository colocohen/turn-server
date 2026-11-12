/**
 * UDP socket buffer sizes — one rule for every socket that carries media:
 * here, the ICE agent's host sockets, the TURN server's UDP listener, its
 * relay sockets (one per allocation) and a TURN client's transport; and
 * webrtc-server's WebRTCRouter socket (exported for it from index.js). A
 * module of its own because all of them use it: one default, one check.
 *
 * The OS default receive buffer (Linux: 208 KB) holds about 180 datagrams.
 * A WebRTC data channel at full rate delivers them in bursts faster than one
 * event-loop turn drains them: measured against Chromium on loopback, a
 * 32 MB transfer lost 300–1,600 datagrams in the kernel — each one
 * retransmitted and a congestion-window cut — at 4 MB, none. The kernel
 * caps the request at net.core.rmem_max / wmem_max, silently.
 */

const DEFAULT_SOCKET_BUFFER_SIZE = 4 << 20;

/**
 * The size an option asks for: undefined — the default; 0 or false — the
 * OS's own; a positive integer — that many bytes. Anything else throws.
 */
function checkedSocketBufferSize(v, what) {
  if (v === undefined || v === null) return DEFAULT_SOCKET_BUFFER_SIZE;
  if (v === 0 || v === false) return 0;
  if (!Number.isInteger(v) || v < 0 || v > 0x7fffffff) {
    throw new RangeError((what || 'socketBufferSize') + ' must be a positive integer (bytes), 0 or false, got ' + v);
  }
  return v;
}

/** dgram.createSocket options with the buffers set (none: as they were). */
function udpSocketOptions(base, size) {
  return size > 0 ? Object.assign({}, base, { recvBufferSize: size, sendBufferSize: size }) : base;
}

export { DEFAULT_SOCKET_BUFFER_SIZE, checkedSocketBufferSize, udpSocketOptions };
