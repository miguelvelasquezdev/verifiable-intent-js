/**
 * Python-parity re-encoding of a *previously signed* JSON segment.
 *
 * Signature verification re-encodes the decoded header/payload objects (never
 * the raw signed bytes) so in-memory mutations are caught. Python's
 * `json.loads`/`json.dumps` round-trip preserves the int/float distinction
 * (`1.0` → `1.0`), but JS `JSON.parse` collapses `1.0` to `1` and rounds
 * integers beyond ±2^53, so a plain `JSON.stringify` re-encode diverges from
 * the signed bytes for those numbers and verification silently fails on
 * credentials Python accepts.
 *
 * This module closes that gap: {@link parsePySegment} re-parses the raw
 * segment text capturing each number's original lexeme (via `JSON.parse`
 * source access), and re-serializes the value exactly as Python's
 * `json.dumps(obj, separators=(",", ":"))` would — `1.0` stays `1.0`, `1e2`
 * becomes `100.0`, big integers keep all their digits, floats outside
 * [1e-4, 1e16) use Python's `e±NN` notation. The caller only uses this
 * re-encoding when the in-memory object is still deep-equal to the parsed
 * segment ({@link pyDeepEqual}), so mutation detection is preserved: any
 * value change falls back to the strict `compactJson` path and the signature
 * check fails, exactly as it does in Python.
 *
 * The lexemes come from a self-contained RFC 8259 parser rather than
 * `JSON.parse` reviver source access, so the behavior is identical on every
 * supported runtime — including Node 20 (this package's `engines` floor) and
 * non-V8 browsers, where source access does not exist.
 */

import { asciiEscape } from './json.js';

/** A number captured with its original JSON lexeme. */
class PyNum {
  constructor(
    readonly value: number,
    readonly source: string,
  ) {}
}

export interface ParsedSegment {
  /** The parsed value, identical to what `JSON.parse(text)` yields. */
  value: unknown;
  /** The segment re-serialized as Python `json.dumps(separators=(",", ":"))` would. */
  pyText: string;
}

/**
 * Parse a JSON segment and compute its Python-compact re-serialization.
 * Returns null when the text is not valid JSON.
 */
export function parsePySegment(text: string): ParsedSegment | null {
  let tree: unknown;
  try {
    tree = parseCapturingNumbers(text);
  } catch {
    return null;
  }
  return walk(tree);
}

/**
 * RFC 8259 parser that keeps each number's original lexeme.
 *
 * `JSON.parse` reviver source access would give the same thing in one line, but
 * it needs V8 12 (Node >= 21) and is absent on Node 20 — this package's
 * `engines` floor — and on non-V8 browsers. There, `parsePySegment` used to
 * return null and every credential carrying `1.0` or an integer beyond 2^53
 * silently failed signature verification, so the "byte-compatible with Python"
 * guarantee held only on new V8. Parsing the text here makes the behavior
 * identical on every supported runtime.
 *
 * Accepts exactly what `JSON.parse` accepts (see the differential test in
 * test/crypto-parity.test.ts) and preserves object key insertion order, which
 * Python's `json.dumps` relies on. Duplicate keys resolve last-wins, as in both
 * `JSON.parse` and Python's `json.loads`.
 */
function parseCapturingNumbers(text: string): unknown {
  let i = 0;

  const fail = (msg: string): never => {
    throw new SyntaxError(`${msg} at position ${i}`);
  };

  const ws = (): void => {
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };

  const literal = (word: string, value: unknown): unknown => {
    if (text.startsWith(word, i)) {
      i += word.length;
      return value;
    }
    return fail(`Unexpected token '${text[i] ?? ''}'`);
  };

  const string = (): string => {
    if (text[i] !== '"') fail('Expected string');
    i++;
    let out = '';
    for (;;) {
      if (i >= text.length) fail('Unterminated string');
      const c = text[i]!;
      if (c === '"') {
        i++;
        return out;
      }
      if (c === '\\') {
        i++;
        const e = text[i];
        i++;
        switch (e) {
          case '"':
            out += '"';
            break;
          case '\\':
            out += '\\';
            break;
          case '/':
            out += '/';
            break;
          case 'b':
            out += '\b';
            break;
          case 'f':
            out += '\f';
            break;
          case 'n':
            out += '\n';
            break;
          case 'r':
            out += '\r';
            break;
          case 't':
            out += '\t';
            break;
          case 'u': {
            const hex = text.slice(i, i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('Invalid \\u escape');
            out += String.fromCharCode(parseInt(hex, 16));
            i += 4;
            break;
          }
          default:
            fail('Invalid escape');
        }
        continue;
      }
      // RFC 8259: unescaped control characters are not allowed in strings.
      if (text.charCodeAt(i) < 0x20) fail('Unescaped control character in string');
      out += c;
      i++;
    }
  };

  const number = (): PyNum => {
    const start = i;
    if (text[i] === '-') i++;
    if (text[i] === '0') {
      i++;
    } else if (text[i] !== undefined && text[i]! >= '1' && text[i]! <= '9') {
      while (text[i] !== undefined && text[i]! >= '0' && text[i]! <= '9') i++;
    } else {
      fail('Invalid number');
    }
    if (text[i] === '.') {
      i++;
      if (!(text[i] !== undefined && text[i]! >= '0' && text[i]! <= '9')) fail('Invalid fraction');
      while (text[i] !== undefined && text[i]! >= '0' && text[i]! <= '9') i++;
    }
    if (text[i] === 'e' || text[i] === 'E') {
      i++;
      if (text[i] === '+' || text[i] === '-') i++;
      if (!(text[i] !== undefined && text[i]! >= '0' && text[i]! <= '9')) fail('Invalid exponent');
      while (text[i] !== undefined && text[i]! >= '0' && text[i]! <= '9') i++;
    }
    const source = text.slice(start, i);
    return new PyNum(Number(source), source);
  };

  const array = (): unknown[] => {
    i++; // '['
    const out: unknown[] = [];
    ws();
    if (text[i] === ']') {
      i++;
      return out;
    }
    for (;;) {
      ws();
      out.push(value());
      ws();
      if (text[i] === ',') {
        i++;
        continue;
      }
      if (text[i] === ']') {
        i++;
        return out;
      }
      fail("Expected ',' or ']'");
    }
  };

  const object = (): Record<string, unknown> => {
    i++; // '{'
    const out: Record<string, unknown> = {};
    ws();
    if (text[i] === '}') {
      i++;
      return out;
    }
    for (;;) {
      ws();
      const key = string();
      ws();
      if (text[i] !== ':') fail("Expected ':'");
      i++;
      ws();
      // Plain assignment: a duplicate key takes the LAST value but keeps its
      // FIRST position, which is what both JSON.parse and Python's json.loads
      // do (and key order is part of the re-serialized bytes).
      out[key] = value();
      ws();
      if (text[i] === ',') {
        i++;
        continue;
      }
      if (text[i] === '}') {
        i++;
        return out;
      }
      fail("Expected ',' or '}'");
    }
  };

  function value(): unknown {
    const c = text[i];
    if (c === undefined) return fail('Unexpected end of input');
    if (c === '{') return object();
    if (c === '[') return array();
    if (c === '"') return string();
    if (c === 't') return literal('true', true);
    if (c === 'f') return literal('false', false);
    if (c === 'n') return literal('null', null);
    if (c === '-' || (c >= '0' && c <= '9')) return number();
    return fail(`Unexpected token '${c}'`);
  }

  ws();
  const result = value();
  ws();
  if (i !== text.length) fail('Unexpected trailing content');
  return result;
}

function walk(node: unknown): ParsedSegment {
  if (node instanceof PyNum) {
    return { value: node.value, pyText: pyNumberText(node) };
  }
  if (node === null || typeof node === 'boolean') {
    return { value: node, pyText: String(node) };
  }
  if (typeof node === 'string') {
    return { value: node, pyText: asciiEscape(JSON.stringify(node)) };
  }
  if (Array.isArray(node)) {
    const items = node.map(walk);
    return { value: items.map((i) => i.value), pyText: `[${items.map((i) => i.pyText).join(',')}]` };
  }
  // JSON.parse can only produce plain objects beyond the cases above.
  const obj = node as Record<string, unknown>;
  const value: Record<string, unknown> = {};
  const parts: string[] = [];
  for (const key of Object.keys(obj)) {
    const item = walk(obj[key]);
    value[key] = item.value;
    parts.push(`${asciiEscape(JSON.stringify(key))}:${item.pyText}`);
  }
  return { value, pyText: `{${parts.join(',')}}` };
}

/**
 * Render a parsed number as Python `json.dumps` would.
 *
 * A lexeme without `.`/`e`/`E` is a Python int: all digits are kept exactly
 * (BigInt, so nothing rounds) and `-0` canonicalizes to `0`. Anything else is
 * a Python float, rendered with `repr` semantics: shortest round-trip digits
 * (shared with JS), `.0` suffix on integral values, and `e±NN` scientific
 * notation only outside [1e-4, 1e16) — where JS `String()` would disagree.
 */
function pyNumberText(num: PyNum): string {
  const { value, source } = num;
  if (!/[.eE]/.test(source)) {
    return BigInt(source).toString();
  }
  if (Object.is(value, -0)) return '-0.0';
  if (Number.isInteger(value) && Math.abs(value) < 1e16) return `${value}.0`;
  const [mantissa, expPart] = value.toExponential().split('e') as [string, string];
  const exp = Number(expPart);
  if (exp < -4 || exp >= 16) {
    return `${mantissa}e${exp < 0 ? '-' : '+'}${String(Math.abs(exp)).padStart(2, '0')}`;
  }
  return String(value);
}

/**
 * Order-sensitive deep equality between a parsed segment value and a live
 * object. Numbers compare with `Object.is` so a `-0` → `0` mutation is caught
 * (Python re-encodes the mutated value and the signature fails). Object key
 * *order* participates because Python's `json.dumps` serializes dicts in
 * insertion order — reordered keys change the signed bytes.
 */
export function pyDeepEqual(a: unknown, b: unknown): boolean {
  if (typeof a === 'number' || typeof b === 'number') {
    return Object.is(a, b);
  }
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') {
    return a === b;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => pyDeepEqual(v, b[i]));
  }
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  if (aKeys.length !== bKeys.length) return false;
  return aKeys.every((k, i) => k === bKeys[i] && pyDeepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}
