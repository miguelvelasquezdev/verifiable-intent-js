/**
 * Regression tests for three TS↔Python divergences found in review, plus the
 * TS-native diagnostics that were deliberately NOT unified with Python.
 *
 * Cases 1-3 were executed against BOTH implementations before the fix; where a
 * Python behaviour is cited in a comment it is transcribed from an actual run of
 * `python/src/verifiable_intent`, not guessed.
 *
 *  1. A non-string L2 `cnf.jwk.kid` used to be coerced to null, which silently
 *     SKIPPED the L3 header-kid binding check — the chain verified `valid: true`
 *     where Python rejected it.
 *  2. A float-spelled integer amount (`27999.0`) passed `Number.isInteger`,
 *     so TS accepted an L3a that Python rejects via `isinstance(amount, int)`.
 *  3. `b64urlDecode` skipped out-of-alphabet characters, so a disclosure with a
 *     `$` spliced into it decoded back to valid JSON instead of failing.
 *  4. Error strings on the fail-closed paths below are NOT byte-identical to the
 *     Python reference. That is deliberate: the golden vectors pin 11 error
 *     strings, none of which render a type name or an absent value, so nothing
 *     compares these across implementations — and a TS SDK reporting Python type
 *     names (`dict`, `NoneType`) would describe the caller's data in the wrong
 *     language. These cases pin the TS-native wording so it cannot drift
 *     silently; `verification.test.ts` still asserts the vector-pinned strings
 *     byte-for-byte.
 */

import { describe, expect, it } from 'vitest';

import {
  AllowedMerchantConstraint,
  buildSelectivePresentation,
  CheckoutL3Mandate,
  CheckoutLineItemsConstraint,
  CheckoutMandate,
  checkConstraints,
  createLayer1,
  createLayer2Autonomous,
  createLayer3Checkout,
  createLayer3Payment,
  createSdJwt,
  type DecodedDisclosure,
  decodeDisclosure,
  type Es256Jwk,
  FinalCheckoutMandate,
  FinalPaymentMandate,
  generateEs256Key,
  hashAscii,
  hashDisclosure,
  IssuerCredential,
  type JsonObject,
  jwtEncode,
  makeSigner,
  MandateMode,
  PaymentAmountConstraint,
  PaymentL3Mandate,
  PaymentMandate,
  type SdJwt,
  UserMandate,
  verifyChain,
} from '../src/index.js';
import { b64urlDecode, b64urlEncode, utf8 } from '../src/crypto/base64url.js';

const MERCHANTS: JsonObject[] = [
  { id: 'merchant-uuid-1', name: 'Tennis Warehouse', website: 'https://tennis-warehouse.com' },
  { id: 'merchant-uuid-2', name: 'Babolat', website: 'https://babolat.com' },
];
const ACCEPTABLE_ITEMS: JsonObject[] = [
  { id: 'BAB86345', title: 'Babolat Pure Aero Tennis Racket' },
  { id: 'HEA23102', title: 'Head Graphene 360 Speed' },
];
const PAYMENT_INSTRUMENT: JsonObject = {
  type: 'mastercard.srcDigitalCard',
  id: 'f199c3dd-7106-478b-9b5f-7af9ca725170',
  description: 'Mastercard **** 1234',
};
const NOW = 1_700_000_000;
const L1_VCT = 'https://credentials.mastercard.com/card';

type KeyPair = { publicKey: Es256Jwk; privateKey: Es256Jwk };
const jwkOf = (k: KeyPair): JsonObject => k.publicKey as unknown as JsonObject;

function deterministicSalts(): () => string {
  let n = 0;
  return () => `salt${(n++).toString().padStart(22, '0')}`;
}

function findDisclosure(sd: SdJwt, pred: (v: JsonObject) => boolean): string {
  for (const disc of sd.disclosures) {
    const dv: DecodedDisclosure = decodeDisclosure(disc);
    const value = dv.length ? dv[dv.length - 1] : null;
    if (value && typeof value === 'object' && !Array.isArray(value) && pred(value as JsonObject)) return disc;
  }
  throw new Error('expected disclosure not found');
}

interface Chain {
  issuer: KeyPair;
  agent: KeyPair;
  l1: SdJwt;
  l1Ser: string;
  l2: SdJwt;
  l2Ser: string;
  l3a: SdJwt;
  l3b: SdJwt;
  l2PaymentSer: string;
  l2CheckoutSer: string;
  checkoutHash: string;
}

/**
 * Full autonomous chain. `kidSpec` controls both mandates' `cnf.jwk.kid`:
 * `{ kid: v }` sets it to `v` verbatim, `{}` omits the member entirely.
 */
async function makeChain(
  kidSpec: { kid?: unknown } = { kid: 'agent-key-1' },
  l3HeaderKid = 'agent-key-1',
): Promise<Chain> {
  const io = { saltSource: deterministicSalts() };
  const issuer = await generateEs256Key();
  const user = await generateEs256Key();
  const agent = await generateEs256Key();
  const merchant = await generateEs256Key();

  const l1 = await createLayer1(
    new IssuerCredential({
      iss: 'https://www.mastercard.com',
      sub: 'userCredentialId',
      iat: NOW,
      exp: NOW + 86400,
      aud: 'https://wallet.example.com',
      email: 'test@example.com',
      panLastFour: '1234',
      scheme: 'Mastercard',
      cnfJwk: jwkOf(user),
    }),
    issuer.privateKey,
    io,
  );
  const l1Ser = l1.serialize();

  // cnfKid is typed `string | null`, so a non-string kid is injected via the jwk.
  const agentJwk = ('kid' in kidSpec ? { ...jwkOf(agent), kid: kidSpec.kid } : { ...jwkOf(agent) }) as JsonObject;

  const l2 = await createLayer2Autonomous(
    new UserMandate({
      nonce: 'n-auto',
      aud: 'https://www.agent.com',
      iat: NOW,
      iss: 'https://wallet.example.com',
      exp: NOW + 86400,
      mode: MandateMode.AUTONOMOUS,
      sdHash: await hashAscii(l1Ser),
      checkoutMandate: new CheckoutMandate({
        vct: 'mandate.checkout.open.1',
        cnfJwk: agentJwk,
        cnfKid: null,
        constraints: [
          new AllowedMerchantConstraint({ allowed: MERCHANTS }),
          new CheckoutLineItemsConstraint({
            items: [{ id: 'line-item-1', acceptable_items: ACCEPTABLE_ITEMS.slice(0, 1), quantity: 1 }],
          }),
        ],
      }),
      paymentMandate: new PaymentMandate({
        vct: 'mandate.payment.open.1',
        cnfJwk: agentJwk,
        cnfKid: null,
        paymentInstrument: PAYMENT_INSTRUMENT,
        constraints: [new PaymentAmountConstraint({ currency: 'USD', min: 10000, max: 40000 })],
      }),
      merchants: MERCHANTS,
      acceptableItems: ACCEPTABLE_ITEMS,
    }),
    user.privateKey,
    io,
  );
  const l2Ser = l2.serialize();
  const l2BaseJwt = l2Ser.split('~')[0] ?? '';
  const paymentDisc = findDisclosure(l2, (v) => v.vct === 'mandate.payment.open.1');
  const checkoutDisc = findDisclosure(l2, (v) => v.vct === 'mandate.checkout.open.1');
  const merchantDisc = findDisclosure(l2, (v) => v.name === 'Tennis Warehouse');
  const itemDisc = findDisclosure(l2, (v) => v.id === 'BAB86345');

  const checkoutJwt = await jwtEncode(
    { alg: 'ES256', typ: 'JWT', kid: 'merchant-key-1' },
    { iss: 'https://tennis-warehouse.com', sub: 'cart_checkout', iat: NOW, exp: NOW + 3600 },
    await makeSigner(merchant.privateKey),
  );
  const checkoutHash = await hashAscii(checkoutJwt);

  let l3a = await createLayer3Payment(
    new PaymentL3Mandate({
      nonce: 'n-l3a',
      aud: 'https://www.mastercard.com',
      iat: NOW,
      iss: 'https://agent.example.com',
      exp: NOW + 300,
      finalPayment: new FinalPaymentMandate({
        transactionId: checkoutHash,
        payee: MERCHANTS[0],
        paymentAmount: { currency: 'USD', amount: 27999 },
        paymentInstrument: PAYMENT_INSTRUMENT,
      }),
      finalMerchant: MERCHANTS[0],
    }),
    agent.privateKey,
    { l2BaseJwt, paymentDisclosure: paymentDisc, merchantDisclosure: merchantDisc },
    io,
  );
  let l3b = await createLayer3Checkout(
    new CheckoutL3Mandate({
      nonce: 'n-l3b',
      aud: 'https://tennis-warehouse.com',
      iat: NOW,
      iss: 'https://agent.example.com',
      exp: NOW + 300,
      finalCheckout: new FinalCheckoutMandate({ checkoutJwt, checkoutHash }),
    }),
    agent.privateKey,
    { l2BaseJwt, checkoutDisclosure: checkoutDisc, itemDisclosure: itemDisc },
    io,
  );
  if (l3HeaderKid !== 'agent-key-1') {
    l3a = await createSdJwt({ ...l3a.header, kid: l3HeaderKid }, l3a.payload, l3a.disclosures, agent.privateKey);
    l3b = await createSdJwt({ ...l3b.header, kid: l3HeaderKid }, l3b.payload, l3b.disclosures, agent.privateKey);
  }

  return {
    issuer,
    agent,
    l1,
    l1Ser,
    l2,
    l2Ser,
    l3a,
    l3b,
    l2PaymentSer: buildSelectivePresentation(l2BaseJwt, [paymentDisc, merchantDisc]),
    l2CheckoutSer: buildSelectivePresentation(l2BaseJwt, [checkoutDisc, itemDisc]),
    checkoutHash,
  };
}

function fullOpts(c: Chain, l3Payment: SdJwt | null, l3Checkout: SdJwt | null) {
  return {
    splitL3s: [
      { l3Payment, l3Checkout, l2PaymentSerialized: c.l2PaymentSer, l2CheckoutSerialized: c.l2CheckoutSer },
    ],
    issuerPublicJwk: c.issuer.publicKey,
    l1Serialized: c.l1Ser,
    l2Serialized: c.l2Ser,
    currentTime: NOW,
  };
}

describe('L3 header-kid binding with a non-string L2 cnf.jwk.kid', () => {
  it('rejects a mismatched L3 kid when L2 pins a numeric kid', async () => {
    // Python: "L3a (payment) header kid 'totally-unrelated-kid' does not match
    //          L2 cnf.jwk.kid '12345'"  (kid kept as int by `jwk.get("kid")`).
    const c = await makeChain({ kid: 12345 }, 'totally-unrelated-kid');
    const r = await verifyChain(c.l1, c.l2, fullOpts(c, c.l3a, c.l3b));
    expect(r.valid).toBe(false);
    expect(r.errors[0]).toBe(
      "L3a (payment) header kid 'totally-unrelated-kid' does not match L2 cnf.jwk.kid '12345'",
    );
  });

  it('leaves the binding unpinned when L2 omits kid', async () => {
    // Python: `jwk.get("kid")` -> None -> `agent_kid is not None` is False, so
    // the L3 header kid is not compared at all.
    const c = await makeChain({}, 'any-kid-at-all');
    const r = await verifyChain(c.l1, c.l2, fullOpts(c, c.l3a, c.l3b));
    expect(r.valid).toBe(true);
  });

  it('treats an explicit null kid as unpinned, like Python dict.get', async () => {
    const c = await makeChain({ kid: null }, 'any-kid-at-all');
    const r = await verifyChain(c.l1, c.l2, fullOpts(c, c.l3a, c.l3b));
    expect(r.valid).toBe(true);
  });

  it('accepts the normal string-kid chain', async () => {
    const c = await makeChain({ kid: 'agent-key-1' }, 'agent-key-1');
    const r = await verifyChain(c.l1, c.l2, fullOpts(c, c.l3a, c.l3b));
    expect(r.valid).toBe(true);
  });
});

describe('float-spelled integer amounts', () => {
  it('rejects an L3a whose payment_amount.amount is written 27999.0', async () => {
    // Python: "L3a (payment) payment mandate payment_amount field 'amount' must
    //          be an integer" — json.loads gives a float, isinstance(_, int) fails.
    const c = await makeChain();
    const mandate = {
      vct: 'mandate.payment.1',
      transaction_id: c.checkoutHash,
      payee: MERCHANTS[0],
      payment_amount: { currency: 'USD', amount: 27999 },
      payment_instrument: PAYMENT_INSTRUMENT,
    };
    const text = JSON.stringify(['saltAAAAAAAAAAAAAAAAAA', 'x', mandate]).replace(
      '"amount":27999',
      '"amount":27999.0',
    );
    const disc = b64urlEncode(utf8(text));
    const h = await hashDisclosure(disc);
    const l3a = await createSdJwt(
      c.l3a.header,
      { ...c.l3a.payload, _sd: [h], delegate_payload: [{ '...': h }] },
      [disc],
      c.agent.privateKey,
    );
    const r = await verifyChain(c.l1, c.l2, {
      splitL3s: [{ l3Payment: l3a, l3Checkout: null, l2PaymentSerialized: c.l2PaymentSer }],
      issuerPublicJwk: c.issuer.publicKey,
      l1Serialized: c.l1Ser,
      l2Serialized: c.l2Ser,
      currentTime: NOW,
    });
    expect(r.valid).toBe(false);
    expect(r.errors[0]).toBe("L3a (payment) payment mandate payment_amount field 'amount' must be an integer");
  });

  it('checkConstraints rejects a float-spelled amount from a disclosure', () => {
    const text = '["saltAAAAAAAAAAAAAAAAAA","x",{"payment_amount":{"currency":"USD","amount":27999.0}}]';
    const dv = decodeDisclosure(b64urlEncode(utf8(text)));
    const fulfillment = dv[dv.length - 1] as JsonObject;
    const r = checkConstraints([{ type: 'mandate.payment.amount_range', currency: 'USD', max: 40000 }], fulfillment);
    expect(r.satisfied).toBe(false);
    expect(r.violations).toContain(
      'Invalid amount: must be an integer, got a number written with a decimal point or exponent: 27999',
    );
  });

  it('still accepts an ordinary integer amount', () => {
    const text = '["saltAAAAAAAAAAAAAAAAAA","x",{"payment_amount":{"currency":"USD","amount":27999}}]';
    const dv = decodeDisclosure(b64urlEncode(utf8(text)));
    const r = checkConstraints(
      [{ type: 'mandate.payment.amount_range', currency: 'USD', max: 40000 }],
      dv[dv.length - 1] as JsonObject,
    );
    expect(r.satisfied).toBe(true);
  });
});

describe('b64urlDecode rejects non-canonical base64url', () => {
  it('rejects out-of-alphabet characters instead of silently skipping them', () => {
    expect(() => b64urlDecode('AAAA$A')).toThrow(/unexpected character/);
    expect(() => b64urlDecode('AAAA A')).toThrow(/unexpected character/);
    // A valid disclosure with a `$` spliced in used to decode back to the
    // ORIGINAL JSON (the junk character was skipped, restoring the bit stream).
    const spliced = 'WyJzYWx0$QUFBQUFBQUFBQUFBQUFBQUFBIiwiZW1haWwiLCJ0ZXN0QGV4YW1wbGUuY29tIl0';
    expect(() => decodeDisclosure(spliced)).toThrow();
  });

  it('rejects padding (RFC 4648 §5 unpadded form only)', () => {
    expect(() => b64urlDecode('AA==')).toThrow(/unexpected character/);
    expect(() => b64urlDecode('AAA=')).toThrow(/unexpected character/);
  });

  it('keeps the existing length and non-ASCII guards', () => {
    expect(() => b64urlDecode('AAAAA')).toThrow(/not a valid base64 length/);
    expect(() => b64urlDecode('éééé')).toThrow(/non-ASCII/);
  });

  it('round-trips canonical output unchanged', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    expect(Array.from(b64urlDecode(b64urlEncode(bytes)))).toEqual([1, 2, 3, 4, 5]);
    for (let n = 0; n <= 32; n++) {
      const b = new Uint8Array(n).map((_, i) => (i * 37) & 0xff);
      expect(Array.from(b64urlDecode(b64urlEncode(b)))).toEqual(Array.from(b));
    }
  });
});

describe('fail-closed diagnostics use TS-native type names', () => {
  const base = async (): Promise<Chain> => makeChain();

  it('rejects a non-ES256 alg', async () => {
    const c = await base();
    const bad = await createSdJwt({ ...c.l1.header, alg: 'RS256' }, c.l1.payload, c.l1.disclosures, c.issuer.privateKey);
    const r = await verifyChain(bad, c.l2, { skipIssuerVerification: true, currentTime: NOW });
    expect(r.errors[0]).toBe("L1 header alg must be one of {ES256}, got string 'RS256'");
  });

  it('rejects an absent alg', async () => {
    const c = await base();
    const header: Record<string, unknown> = { ...c.l1.header };
    delete header.alg;
    const bad = await createSdJwt(header, c.l1.payload, c.l1.disclosures, c.issuer.privateKey);
    const r = await verifyChain(bad, c.l2, { skipIssuerVerification: true, currentTime: NOW });
    expect(r.errors[0]).toBe("L1 header alg must be one of {ES256}, got undefined 'undefined'");
  });

  it('rejects a numeric typ', async () => {
    const c = await base();
    const bad = await createSdJwt({ ...c.l1.header, typ: 7 }, c.l1.payload, c.l1.disclosures, c.issuer.privateKey);
    const r = await verifyChain(bad, c.l2, { skipIssuerVerification: true, currentTime: NOW });
    expect(r.errors[0]).toBe("L1 header typ must be 'sd+jwt', got number '7'");
  });

  it('rejects an absent vct', async () => {
    const c = await base();
    const payload: Record<string, unknown> = { ...c.l1.payload };
    delete payload.vct;
    const bad = await createSdJwt(c.l1.header, payload, c.l1.disclosures, c.issuer.privateKey);
    const r = await verifyChain(bad, c.l2, { skipIssuerVerification: true, currentTime: NOW });
    expect(r.errors[0]).toBe(`L1 vct must be '${L1_VCT}', got 'undefined'`);
  });

  it('rejects a boolean exp', async () => {
    const c = await base();
    const bad = await createSdJwt(
      c.l1.header,
      { ...c.l1.payload, exp: true },
      c.l1.disclosures,
      c.issuer.privateKey,
    );
    const r = await verifyChain(bad, c.l2, { skipIssuerVerification: true, currentTime: NOW });
    expect(r.errors[0]).toBe('L1 credential expired at true');
  });

  it('rejects a non-array constraints argument', () => {
    expect(checkConstraints({ a: 1 }, {}).violations[0]).toBe('Constraints must be a list, got object');
  });

  it('rejects a non-object fulfillment', () => {
    expect(checkConstraints([], null).violations[0]).toBe('Fulfillment must be an object, got null');
    expect(checkConstraints([], 'x').violations[0]).toBe('Fulfillment must be an object, got string');
  });
});

