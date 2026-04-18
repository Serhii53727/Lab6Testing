import crypto from 'node:crypto';
import { ed448 } from '@noble/curves/ed448.js';

const toBytes = (hex) => {
  const clean = String(hex || '').replace(/[^0-9a-f]/gi, '');
  return Uint8Array.from(Buffer.from(clean, 'hex'));
};

const wrapPkcs8 = (seed) => Buffer.concat([
  Buffer.from('3047020100300506032b6571043b0439', 'hex'), 
  seed
]);

const wrapSpki = (pub) => Buffer.concat([
  Buffer.from('3043300506032b6571033a00', 'hex'), 
  pub
]);

export const cryptoProviders = {
  nobleCurves: {
    name: '@noble/curves (JS)',
    sign: (msg, sk, ctx = '') => {
      const sig = ed448.sign(toBytes(msg), toBytes(sk), ctx ? { context: toBytes(ctx) } : undefined);
      return Buffer.from(sig).toString('hex');
    },
    verify: (sig, msg, pk, ctx = '') => {
      return ed448.verify(toBytes(sig), toBytes(msg), toBytes(pk), ctx ? { context: toBytes(ctx) } : undefined);
    }
  },

  nodeCrypto: {
    name: 'node:crypto (Native)',
    sign: (msg, sk, ctx = '') => {
      const key = crypto.createPrivateKey({
        key: wrapPkcs8(toBytes(sk)),
        format: 'der',
        type: 'pkcs8'
      });
      const sig = crypto.sign(undefined, toBytes(msg), {
        key,
        context: ctx ? Buffer.from(ctx, 'hex') : undefined
      });
      return sig.toString('hex');
    },
    verify: (sig, msg, pk, ctx = '') => {
      const key = crypto.createPublicKey({
        key: wrapSpki(toBytes(pk)),
        format: 'der',
        type: 'spki'
      });
      return crypto.verify(
        undefined, 
        toBytes(msg), 
        { key, context: ctx ? Buffer.from(ctx, 'hex') : undefined }, 
        toBytes(sig)
      );
    }
  }
};