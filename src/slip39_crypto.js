let crypto;
try {
  crypto = require('crypto');
} catch (err) {
  throw new Error('crypto support must be enabled');
}

// [Crypto | Node.js v14.4.0 Documentation](https://nodejs.org/api/crypto.html#crypto_crypto_randombytes_size_callback)
function randomBytes(size, callback) {
  return crypto.randomBytes(size, callback)
}

// [Crypto | Node.js v14.4.0 Documentation](https://nodejs.org/api/crypto.html#crypto_crypto_pbkdf2sync_password_salt_iterations_keylen_digest)
function pbkdf2Sync(password, salt, iterations, keylen, digest) {
  return crypto.pbkdf2Sync(password, salt, iterations, keylen, digest)
}

// [Crypto | Node.js v14.4.0 Documentation](https://nodejs.org/api/crypto.html#crypto_crypto_createhmac_algorithm_key_options)
function createHmac(algorithm, key, options) {
  return crypto.createHmac(algorithm, key, options)
}

exports = module.exports = {
  randomBytes,
  pbkdf2Sync,
  createHmac,
};
