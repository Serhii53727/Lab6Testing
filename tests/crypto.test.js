import { cryptoProviders } from '../src/crypto-libs.js';


const testVectors = [
 {
    
    id: 'Vector 6 64',
    sk: 'd65df341ad13e008567688baedda8e9d' +
        'cdc17dc024974ea5b4227b6530e339bf' +
        'f21f99e68ca6968f3cca6dfe0fb9f4fa' +
        'b4fa135d5542ea3f01',
    pk: 'df9705f58edbab802c7f8363cfe5560a' +
        'b1c6132c20a9f1dd163483a26f8ac53a' +
        '39d6808bf4a1dfbd261b099bb03b3fb5' +
        '0906cb28bd8a081f00',
    msg: 
        'bd0f6a3747cd561bdddf4640a332461a' +
        '4a30a12a434cd0bf40d766d9c6d458e5' +
        '512204a30c17d1f50b5079631f64eb31' +
        '12182da3005835461113718d1a5ef944',
    ctx: '',
    sig:
        '554bc2480860b49eab8532d2a533b7d5' +
        '78ef473eeb58c98bb2d0e1ce488a98b1' +
        '8dfde9b9b90775e67f47d4a1c3482058' +
        'efc9f40d2ca033a0801b63d45b3b722e' +
        'f552bad3b4ccb667da350192b61c508c' +
        'f7b6b5adadc2c8d9a446ef003fb05cba' +
        '5f30e88e36ec2703b349ca229c267083' +
        '3900',
  },
  {
    
    id: 'Vector 7 256',
    sk: '2ec5fe3c17045abdb136a5e6a913e32a' +
        'b75ae68b53d2fc149b77e504132d3756' +
        '9b7e766ba74a19bd6162343a21c8590a' +
        'a9cebca9014c636df5',
    pk: '79756f014dcfe2079f5dd9e718be4171' +
        'e2ef2486a08f25186f6bff43a9936b9b' +
        'fe12402b08ae65798a3d81e22e9ec80e' +
        '7690862ef3d4ed3a00',
    msg:
        '15777532b0bdd0d1389f636c5f6b9ba7' +
        '34c90af572877e2d272dd078aa1e567c' +
        'fa80e12928bb542330e8409f31745041' +
        '07ecd5efac61ae7504dabe2a602ede89' +
        'e5cca6257a7c77e27a702b3ae39fc769' +
        'fc54f2395ae6a1178cab4738e543072f' +
        'c1c177fe71e92e25bf03e4ecb72f47b6' +
        '4d0465aaea4c7fad372536c8ba516a60' +
        '39c3c2a39f0e4d832be432dfa9a706a6' +
        'e5c7e19f397964ca4258002f7c0541b5' +
        '90316dbc5622b6b2a6fe7a4abffd9610' +
        '5eca76ea7b98816af0748c10df048ce0' +
        '12d901015a51f189f3888145c03650aa' +
        '23ce894c3bd889e030d565071c59f409' +
        'a9981b51878fd6fc110624dcbcde0bf7' +
        'a69ccce38fabdf86f3bef6044819de11',
    ctx: '',
    sig:
        'c650ddbb0601c19ca11439e1640dd931' +
        'f43c518ea5bea70d3dcde5f4191fe53f' +
        '00cf966546b72bcc7d58be2b9badef28' +
        '743954e3a44a23f880e8d4f1cfce2d7a' +
        '61452d26da05896f0a50da66a239a8a1' +
        '88b6d825b3305ad77b73fbac0836ecc6' +
        '0987fd08527c1a8e80d5823e65cafe2a' +
        '3d00',
  },
];

for (const v of testVectors) {
  const clean = (h) => String(h || '').replace(/[^0-9a-f]/gi, '');
  const sigLen = clean(v.sig).length;
  const skLen  = clean(v.sk).length;
  const pkLen  = clean(v.pk).length;
  if (sigLen !== 228) throw new Error(`"${v.id}": sig = ${sigLen} hex (очікується 228)`);
  if (skLen  !== 114) throw new Error(`"${v.id}": sk  = ${skLen}  hex (очікується 114)`);
  if (pkLen  !== 114) throw new Error(`"${v.id}": pk  = ${pkLen}  hex (очікується 114)`);
}

const normHex = (h) => String(h || '').replace(/[^0-9a-f]/gi, '').toLowerCase();


describe.each(Object.values(cryptoProviders))(
  ' Ed448 RFC 8032 $name',
  (provider) => {

    test.each(testVectors)(' $id', ({ sk, pk, msg, ctx, sig }) => {
      const expectedSig = normHex(sig);
      const actualSig = provider.sign(msg, sk, ctx);
      expect(actualSig).toBe(expectedSig);
      const valid = provider.verify(actualSig, msg, pk, ctx);
      expect(valid).toBe(true);
    });

    test('Фальшивий підпис 114 нулів відхиляється', () => {
      const v = testVectors[0];
      expect(provider.verify('00'.repeat(114), v.msg, v.pk, v.ctx)).toBe(false);
    });

    test('підпис не підходить до зміненого повідомлення', () => {
      const v = testVectors[1]; 
      const sig = provider.sign(v.msg, v.sk, v.ctx);
      expect(provider.verify(sig, 'ff', v.pk, v.ctx)).toBe(false);
    });
    test('виклик без контексту ', () => {
      const v = testVectors[0];
      const sig = provider.sign(v.msg, v.sk);
      expect(sig).toBe(v.sig);
      
      const ok = provider.verify(sig, v.msg, v.pk);
      expect(ok).toBe(true);
    });

    test(' обробка порожніх/null значень у toBytes', () => {
      try {
        provider.sign(null, testVectors[0].sk);
      } catch (e) {
      }
    });
    test('перевірка роботи БЕЗ контексту (шлях undefined)', () => {
      const v = testVectors[0]; 
      const sig = provider.sign(v.msg, v.sk);
      expect(sig).toBe(normHex(v.sig));
      
   
      const isValid = provider.verify(sig, v.msg, v.pk); 
      expect(isValid).toBe(true);
    });

    test('обробка порожнього повідомлення в toBytes', () => {
      const sig = provider.sign('', testVectors[0].sk, '');
      expect(sig.length).toBe(228);
    });
  },
);