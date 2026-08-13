/**
 * Differential test for the RFC 8259 parser behind `parsePySegment`.
 *
 * It replaced `JSON.parse` reviver source access, which only exists on V8 12+
 * (Node >= 21) — on Node 20 and non-V8 browsers `parsePySegment` returned null
 * and Python-number parity silently disappeared. Since the parser now sits on
 * the signature-verification path, it must accept EXACTLY what `JSON.parse`
 * accepts and produce deep-equal values, on every runtime.
 */

import { describe, expect, it } from 'vitest';

import { parsePySegment } from '../src/crypto/py-json.js';

/** `JSON.parse` outcome, normalized for comparison. */
function viaJsonParse(text: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

function viaParser(text: string): { ok: true; value: unknown } | { ok: false } {
  const r = parsePySegment(text);
  return r === null ? { ok: false } : { ok: true, value: r.value };
}

const VALID = [
  '{}',
  '[]',
  'null',
  'true',
  'false',
  '0',
  '-0',
  '1',
  '-1',
  '1.5',
  '1e5',
  '1E5',
  '1e+5',
  '1e-5',
  '-1.5e-5',
  '0.0001',
  '9007199254740993',
  '123456789012345678901234567890',
  '""',
  '"abc"',
  '"a\\"b"',
  '"a\\\\b"',
  '"a\\/b"',
  '"\\b\\f\\n\\r\\t"',
  '"\\u00e9\\u4e2d"',
  '"café"',
  '"rawcontrol"',
  '[1,2,3]',
  '[[[]]]',
  '{"a":1}',
  '{"a":{"b":[1,2,{"c":null}]}}',
  '{"dup":1,"dup":2.5}',
  '{"dup":1,"a":2,"dup":3}',
  '  {  "a"  :  1  ,  "b"  :  [  ]  }  ',
  '{"":0}',
  '[1,-2,3.0,4e0]',
  '{"nested":{"deep":{"deeper":[true,false,null]}}}',
];

const INVALID = [
  '',
  '   ',
  '{',
  '}',
  '[',
  ']',
  '{,}',
  '[,]',
  '[1,]',
  '{"a":1,}',
  "{'a':1}",
  '{a:1}',
  '{"a"1}',
  '{"a":}',
  '01',
  '-',
  '+1',
  '.5',
  '1.',
  '1e',
  '1e+',
  '--1',
  '1 2',
  'nul',
  'tru',
  'True',
  'NaN',
  'Infinity',
  '"unterminated',
  '"bad \\x escape"',
  '"\\u00zz"',
  '{"a":1}{"b":2}',
  '[1 2]',
  '"raw\u0001control"',
  'undefined',
  "'single'",
];

describe('parseCapturingNumbers matches JSON.parse', () => {
  it.each(VALID)('accepts %j with a deep-equal value', (text) => {
    const a = viaJsonParse(text);
    const b = viaParser(text);
    expect(a.ok).toBe(true);
    expect(b.ok).toBe(true);
    if (a.ok && b.ok) {
      expect(b.value).toEqual(a.value);
      // Key order participates in the re-serialized bytes Python signs.
      if (a.value && typeof a.value === 'object' && !Array.isArray(a.value)) {
        expect(Object.keys(b.value as object)).toEqual(Object.keys(a.value));
      }
    }
  });

  it.each(INVALID)('rejects %j exactly as JSON.parse does', (text) => {
    expect(viaJsonParse(text).ok).toBe(false);
    expect(viaParser(text).ok).toBe(false);
  });

  it('agrees with JSON.parse across a generated corpus', () => {
    const pool = ['{', '}', '[', ']', '"a"', ':', ',', '1', '-2', '3.5', 'true', 'null', ' ', 'e', '.', '0'];
    // Deterministic LCG — no Math.random, so a failure is always reproducible.
    let seed = 12345;
    const next = (): number => (seed = (seed * 1103515245 + 12345) & 0x7fffffff);
    let compared = 0;
    for (let n = 0; n < 4000; n++) {
      const len = 1 + (next() % 7);
      let text = '';
      for (let k = 0; k < len; k++) text += pool[next() % pool.length];
      const a = viaJsonParse(text);
      const b = viaParser(text);
      expect({ text, ok: b.ok }).toEqual({ text, ok: a.ok });
      if (a.ok && b.ok) expect({ text, v: b.value }).toEqual({ text, v: a.value });
      compared++;
    }
    expect(compared).toBe(4000);
  });

  it('keeps number lexemes so pyText reproduces Python json.dumps', () => {
    // These are the cases JSON.parse alone cannot represent.
    expect(parsePySegment('{"a":1.0}')?.pyText).toBe('{"a":1.0}');
    expect(parsePySegment('{"a":9007199254740993}')?.pyText).toBe('{"a":9007199254740993}');
    expect(parsePySegment('{"a":1e2}')?.pyText).toBe('{"a":100.0}');
    expect(parsePySegment('{"a":-0.0}')?.pyText).toBe('{"a":-0.0}');
    expect(parsePySegment('{"a":279.99}')?.pyText).toBe('{"a":279.99}');
  });
});
