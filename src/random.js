// Random bytes from cryptographic-primitives, as a Buffer (the callers read
// it with Buffer methods: toString('base64'), toString('hex'), readUInt*)

import { random_bytes_sync } from 'cryptographic-primitives/random.js';

function randomBuffer(n) {
  var u8 = random_bytes_sync(n);
  return Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength);
}

export { randomBuffer };
