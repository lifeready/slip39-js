let crypto_web;
let crypto_node;

try {
  crypto_web = window.crypto;
} catch (error) {

  try {
    crypto_node = require('crypto');
  } catch (err) {
    throw new Error('crypto support must be enabled, either via Web Crypto or Node.js crypto');
  }
}

if (crypto_web) {
  console.log("Using Web Crypto")

  var randomBytes = function (size/*, callback*/) {

    var array = new Uint8Array(size)
    crypto_web.getRandomValues(array);

    console.log(`Generated ${size} random bytes: ${array}`)

    return array;
  }

  var pbkdf2Sync = function (password, salt, iterations, keylen, digest) {
    var derived = null;
    return derived;
  }

  var createDigest = function (randomData, sharedSecret) {

    const key = crypto_web.subtle.importKey(
      "raw", //format,
      Buffer.from(randomData), //keyData,
      {
        name: "HMAC",
        hash: "SHA-256"
      }, //algorithm,
      true, //extractable,
      ["sign", "verify"], //usages
    );

    const data = Buffer.from(sharedSecret);

    let result = crypto_web.subtle.sign("HMAC", key, data);

    result = result.slice(0, 4);
    return Array.prototype.slice.call(result, 0);
  }
} else if (crypto_node) {
  console.log("Using Node crypto")

  var randomBytes = function (size) {
    var array = crypto_node.randomBytes(size)
    return array;
  }

  var pbkdf2Sync = async function (password, salt, iterations, keylen, digest) {
    var derived = crypto_node.pbkdf2Sync(password, salt, iterations, keylen, digest);
    return derived;
  }

  var createDigest = function (randomData, sharedSecret) {
    const key = Buffer.from(randomData);
    const data = Buffer.from(sharedSecret);

    const hmac = crypto_node.createHmac('sha256', key);
    hmac.update(data);
    let result = hmac.digest();

    result = result.slice(0, 4);
    return Array.prototype.slice.call(result, 0);
  }
}

exports = module.exports = {
  randomBytes,
  pbkdf2Sync,
  createDigest,
};
