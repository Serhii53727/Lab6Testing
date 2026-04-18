const crypto = require('node:crypto');
const { ed448 } = require('@noble/curves/ed448');


const cryptoProviders = {
  nodeCrypto: {
    name: 'node:crypto',
    sign: (messageHex, privateKeyHex) => {
      const privKey = crypto.createPrivateKey({
        key: Buffer.from(privateKeyHex, 'hex'),
        format: 'der',
        type: 'pkcs8'
      });
      return crypto.sign(null, Buffer.from(messageHex, 'hex'), privKey).toString('hex');
    }
  },

  nobleCurves: {
    name: '@noble/curves',
    sign: (messageHex, privateKeyHex) => {
      const signature = ed448.sign(messageHex, privateKeyHex);
      return Buffer.from(signature).toString('hex');
    }
  }
};

module.exports = { cryptoProviders };