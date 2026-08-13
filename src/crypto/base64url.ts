/**
 * base64url (unpadded) helpers, matching the Python reference byte-for-byte.
 *
 * Pure-JS over Uint8Array — no Buffer, no btoa/atob — so the package runs in
 * any Web-standard runtime (browsers and Node >= 20 alike).
 */

const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// Reverse lookup over ASCII: 6-bit value per code point, -1 for non-alphabet.
// Both base64 alphabets are accepted ('+/' map to the same values as '-_'),
// matching Node's base64url decoder (and Python's urlsafe b64decode, which
// only ever translates -_ back to +/).
const DECODE_TABLE = new Int8Array(128).fill(-1);
for (let i = 0; i < 64; i++) {
  DECODE_TABLE[B64URL_ALPHABET.charCodeAt(i)] = i;
}
DECODE_TABLE[0x2b] = 62; // '+'
DECODE_TABLE[0x2f] = 63; // '/'

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function b64urlEncode(data: Uint8Array): string {
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const byte of data) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out += B64URL_ALPHABET[(acc >> bits) & 0x3f];
    }
  }
  if (bits > 0) {
    out += B64URL_ALPHABET[(acc << (6 - bits)) & 0x3f];
  }
  return out;
}

/**
 * Decode canonical unpadded base64url (RFC 4648 §5) — strictly.
 *
 * Every character must be in the alphabet (base64url `-_`, plus the standard
 * `+/` that Python's `urlsafe_b64decode` also accepts), and the length must not
 * be 1 more than a multiple of 4 (an impossible base64 length). Padding (`=`)
 * and any other out-of-alphabet character are rejected outright.
 *
 * This is deliberately STRICTER than Python's `urlsafe_b64decode`, which
 * inherits `binascii`'s lenient mode: it silently discards out-of-alphabet
 * characters and accepts padding, so `"AAAA$A"` and a valid disclosure with a
 * `$` spliced into it decode to *something* rather than failing. Emulating that
 * bug-for-bug is not worth doing — the two decoders disagree in both directions
 * (which input is rejected depends on `len % 4` and where the junk lands), and
 * a verifier accepting non-canonical encodings is exactly the canonicalization
 * ambiguity the VI security model warns about:
 *
 *   "Use base64url encoding without padding (RFC 4648 §5). SHOULD reject padded
 *    input during verification to prevent canonicalization mismatches."
 *   — spec/security-model.md §5.1
 *
 * Rejecting a superset of what Python rejects is fail-closed: no credential
 * that the Python reference refuses is accepted here. Both implementations
 * *emit* canonical unpadded base64url, so every well-formed VI credential —
 * including every golden vector — round-trips unchanged.
 */
export function b64urlDecode(s: string): Uint8Array {
  if (s.length % 4 === 1) {
    throw new Error(`Invalid base64url string: length ${s.length} is not a valid base64 length`);
  }
  // Checked before the alphabet scan so non-ASCII input reports the more
  // specific message (parity with Python's `.encode('ascii')` failure).
  if (NON_ASCII_CHAR.test(s)) {
    throw new Error('Invalid base64url string: contains non-ASCII characters');
  }
  const out = new Uint8Array((s.length * 3) >> 2);
  let n = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < s.length; i++) {
    const value = DECODE_TABLE[s.charCodeAt(i)] ?? -1;
    if (value < 0) {
      throw new Error(`Invalid base64url string: unexpected character '${s[i]}' at index ${i}`);
    }
    acc = (acc << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[n++] = (acc >> bits) & 0xff;
    }
  }
  return out.subarray(0, n);
}

/** UTF-8 encode a string to bytes (compact JSON is ASCII, so this equals the ASCII bytes). */
export function utf8(s: string): Uint8Array {
  return textEncoder.encode(s);
}

/**
 * UTF-8 decode bytes to a string, replacing malformed sequences with U+FFFD —
 * the same lossy behavior as Node's `Buffer.toString('utf8')`.
 */
export function utf8Decode(data: Uint8Array): string {
  return textDecoder.decode(data);
}

const NON_ASCII_CHAR = /[\u0080-\uffff]/;

/**
 * Encode an ASCII string to bytes (used for hashing disclosure strings and
 * sd_hash / checkout_hash inputs). Throws on any code point above 0x7F,
 * matching Python's `str.encode('ascii')` — Node's `'ascii'` encoding would
 * instead silently mangle non-ASCII input (latin1-style), which made TS accept
 * hash bindings over bytes Python refuses to produce.
 */
export function asciiBytes(s: string): Uint8Array {
  if (NON_ASCII_CHAR.test(s)) {
    throw new Error('asciiBytes: input contains non-ASCII characters');
  }
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    out[i] = s.charCodeAt(i);
  }
  return out;
}
