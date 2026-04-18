import { cryptoProviders } from '../src/crypto-libs.js';

describe(' Порівняння продуктивності Ed448', () => {
  const ITERATIONS = 500; 
  const msg = 'bd0f6a3747cd561bdddf4640a332461a4a30a12a434cd0bf40d766d9c6d458e5512204a30c17d1f50b5079631f64eb3112182da3005835461113718d1a5ef944';
  const sk = '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b';
  const pk = '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180';

  const results = [];

  test('Вимірювання швидкості провайдерів', () => {
    Object.values(cryptoProviders).forEach((provider) => {
      for (let i = 0; i < 50; i++) {
        const s = provider.sign(msg, sk);
        provider.verify(s, msg, pk);
      }

      const startSign = performance.now();
      for (let i = 0; i < ITERATIONS; i++) {
        provider.sign(msg, sk);
      }
      const endSign = performance.now();

      const signature = provider.sign(msg, sk);
      const startVerify = performance.now();
      for (let i = 0; i < ITERATIONS; i++) {
        provider.verify(signature, msg, pk);
      }
      const endVerify = performance.now();

      results.push({
        'Бібліотека': provider.name,
        'Підпис (сер. мс)': ((endSign - startSign) / ITERATIONS).toFixed(4),
        'Перевірка (сер. мс)': ((endVerify - startVerify) / ITERATIONS).toFixed(4),
        'Оп/с': Math.round(1000 / ((endSign - startSign) / ITERATIONS))
      });
    });

    console.log('\n РЕЗУЛЬТАТИ ТЕСТУ ПРОДУКТИВНОСТІ:');
    console.table(results);
  });
});