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

  var randomBytes = function (size) {

    var array = new Uint8Array(size)
    crypto_web.getRandomValues(array);

    return array;
  }

  var pbkdf2Sync = async function (password, salt, iterations, keylen, digest) {

    let hash;
    if (digest == "sha256") {
      hash = "SHA-256";
    }

    let keyMaterial = await crypto_web.subtle.importKey(
      "raw",        // format
      password,     // keyData
      "PBKDF2",     // algorithm
      false,        // extractable
      ["deriveKey"] // usages
    );

    let key = await crypto_web.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: iterations,
        hash: hash,
      },                      // algorithm
      keyMaterial,            // baseKey
      {
        name: "HMAC",
        hash: hash,
        length: keylen * 8 // keylen is in bytes, we need bits here
      },                      // derivedKeyAlgorithm
      true,                   // extractable
      ["sign"]                // keyUsages
    );

    let derived = await crypto.subtle.exportKey("raw", key);
    derived = new Uint8Array(derived);

    return derived;
  }

  var createDigest = async function (randomData, sharedSecret) {

    const key = await crypto_web.subtle.importKey(
      "raw",                    //format,
      Buffer.from(randomData),  //keyData,
      {
        name: "HMAC",
        hash: "SHA-256"
      },                        //algorithm,
      true,                     //extractable,
      ["sign"],                 //usages
    );

    const data = Buffer.from(sharedSecret);

    let result = await crypto_web.subtle.sign("HMAC", key, data);
    result = new Uint8Array(result);

    result = result.slice(0, 4);
    result = Array.prototype.slice.call(result, 0);
    return result;
  }
} // ==== ==== ==== ==== ==== ==== ==== ==== ==== ==== ==== ==== ==== ==== ==== ====
else if (crypto_node) {
  console.log("Using Node.js crypto")

  var randomBytes = function (size) {
    var array = crypto_node.randomBytes(size)
    return array;
  }

  var pbkdf2Sync = async function (password, salt, iterations, keylen, digest) {
    var derived = crypto_node.pbkdf2Sync(password, salt, iterations, keylen, digest);
    return derived;
  }

  var createDigest = async function (randomData, sharedSecret) {
    const key = Buffer.from(randomData);
    const data = Buffer.from(sharedSecret);

    const hmac = crypto_node.createHmac('sha256', key);
    hmac.update(data);
    let result = hmac.digest();

    result = result.slice(0, 4);
    result = Array.prototype.slice.call(result, 0);
    return result;
  }
}

exports = module.exports = {
  randomBytes,
  pbkdf2Sync,
  createDigest,
};
