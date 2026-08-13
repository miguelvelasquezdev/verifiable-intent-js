/**
 * Recover the int/float distinction that `JSON.parse` throws away.
 *
 * Python's `json.loads` maps an integer lexeme (`27999`) to `int` and anything
 * with a `.` or an exponent (`27999.0`, `2.7999e4`) to `float`, so the reference
 * implementation's `isinstance(amount, int)` check rejects a float-spelled
 * amount. JS has a single `number` type and `Number.isInteger(27999.0)` is
 * `true`, so a naive port silently ACCEPTS a credential Python rejects — see
 * `validatePaymentMandateRequiredFields` in verification/chain.ts.
 *
 * `JSON.parse` source access (the reviver's `context.source`) would give exact
 * lexemes, but it needs Node >= 21 / V8 12, and a verifier whose verdict depends
 * on the runtime version is worse than one that is uniformly strict. So this
 * module recovers the distinction from the raw text with a small scan that only
 * has to get *string boundaries* right: a number token is preceded — modulo
 * whitespace — by `:` when it is an object value, and the key is the string
 * literal before that `:`.
 *
 * Granularity is the KEY NAME within one disclosure, not a full path: if any
 * `"amount"` anywhere in the disclosure is float-spelled, every object decoded
 * from that disclosure reports `amount` as float-spelled. A VI mandate carries
 * one `payment_amount.amount`, so this is exact in practice, and where it is not
 * it over-reports — which fails closed, the safe direction.
 */

/** Per decoded object: the keys whose numeric value was float-spelled in the source. */
const FLOAT_KEYS = new WeakMap<object, ReadonlySet<string>>();

const WS = new Set([0x20, 0x09, 0x0a, 0x0d]);

/**
 * Keys in `text` whose value is a JSON number written as a float (has `.`, `e`,
 * or `E`). Returns an empty set for text containing no such number.
 */
export function floatSpelledKeys(text: string): ReadonlySet<string> {
  const out = new Set<string>();
  let lastString: string | null = null;
  let pendingKey: string | null = null;

  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;

    if (c === '"') {
      // Consume the string literal, honouring backslash escapes.
      let j = i + 1;
      let raw = '';
      while (j < text.length) {
        const d = text[j]!;
        if (d === '\\') {
          raw += d + (text[j + 1] ?? '');
          j += 2;
          continue;
        }
        if (d === '"') break;
        raw += d;
        j++;
      }
      lastString = raw;
      i = j;
      continue;
    }

    if (c === ':') {
      pendingKey = lastString;
      continue;
    }

    if (c === '-' || (c >= '0' && c <= '9')) {
      // Scan the number token and note whether it is float-spelled.
      let j = i;
      let isFloat = false;
      while (j < text.length) {
        const d = text[j]!;
        if ((d >= '0' && d <= '9') || d === '-' || d === '+') {
          j++;
          continue;
        }
        if (d === '.' || d === 'e' || d === 'E') {
          isFloat = true;
          j++;
          continue;
        }
        break;
      }
      if (isFloat && pendingKey !== null) out.add(pendingKey);
      i = j - 1;
      pendingKey = null;
      continue;
    }

    // Any other structural token ends the pending key/value association.
    if (!WS.has(c.charCodeAt(0))) pendingKey = null;
  }

  return out;
}

/** Associate `keys` with every object reachable from `value` (see module note on granularity). */
export function tagFloatSpelled(value: unknown, keys: ReadonlySet<string>): void {
  if (keys.size === 0) return;
  const seen = new Set<object>();
  const stack: unknown[] = [value];
  while (stack.length) {
    const node = stack.pop();
    if (typeof node !== 'object' || node === null) continue;
    if (seen.has(node)) continue;
    seen.add(node);
    FLOAT_KEYS.set(node, keys);
    for (const child of Object.values(node)) stack.push(child);
  }
}

/** True when `container[key]` came from a float-spelled JSON number (Python would call it a `float`). */
export function isFloatSpelled(container: unknown, key: string): boolean {
  if (typeof container !== 'object' || container === null) return false;
  return FLOAT_KEYS.get(container)?.has(key) ?? false;
}
