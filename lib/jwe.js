
'use strict';

var crypto = require('crypto');
var constants = require('constants');
const base64url = require('base64url');

var aadutils = require('./aadutils');
var aesHmac = require('aes-cbc-hmac-sha2');
var jwkToPem = require('jwk-to-pem');

/*
 * Create a buffer. The usage of 'new Buffer()' is deprecated in v6.0.0, and
 * 'Buffer.from' is introduced in v5.10.0. To support node v4.0.0+, we use
 * 'Buffer.from' for v6.0.0+ and 'new Buffer' for lower versions.
 *
 * data: buffer, string, or size
 * encoding: ignored if data is a buffer
 */
var createBuffer = (data, encoding) => {
  if (!Buffer.isBuffer(data) && typeof data !== 'string' && typeof data !== 'number')
    throw new Error('in createBuffer, data must be a buffer, string or number');

  if (process.version >= 'v6') {
    if (typeof data === 'string')
      return Buffer.from(data, encoding);
    else if (typeof data === 'number')
      return Buffer.alloc(data);
    else
      return Buffer.from(data);
  } else {
    if (typeof data === 'string')
      return new Buffer(data, encoding);
    else
      return new Buffer(data);
  } 
};

var xor = (a, b) => {
  var la = a.length;
  var lb = b.length;
  var c1, c2;
  if (la > lb) {
    c1 = a; c2 =b;
  } else {
    c2 = a; c1 = b;
  }
  var c = createBuffer(c1);
  for (var i = 1; i <= c2.length; i++)
    c[c1.length-i] = c[c1.length-i] ^ c2[c2.length-i];
  return c;
};

var keyWrap = (algorithm, contentKey, kek) => {
  var n = contentKey.length/8;
  var A = createBuffer("A6A6A6A6A6A6A6A6", "hex");
  
  var R = [createBuffer(1)];
  for (var i = 1; i <= n; i++)
    R.push(contentKey.slice(8*i-8, 8*i));

  for(var j=0; j<= 5; j++) {
    for(var i=1; i<= n; i++) {
      var aes = crypto.createCipheriv(algorithm, kek, '');
      aes.setAutoPadding(false);
      var B = aes.update(Buffer.concat([A, R[i]]), null, 'hex');
      B = B + aes.final('hex');
      B = createBuffer(B, 'hex');

      var str = (n*j+i).toString(16);
      if (str.length %2 !== 0)
        str = '0' + str;
      var t = Buffer.from(str, 'hex');

      A = xor(B.slice(0, 8), t);
      R[i] = B.slice(B.length-8);
    }
  }

  var result = createBuffer(A);
  for (var i = 1; i <= n; i++)
    result = Buffer.concat([result, R[i]]);

  return result;
};

var keyUnWrap = (algorithm, cipherText, kek) => {

  /****************************************************************************
   * Inputs: CipherText, (n+1) 64-bit values {C0, C1, ..., Cn}, and 
   *         Key, K (the KEK)
   * Outputs: Plaintext, n 64-bit values {P0, P1, K, Pn}
   ***************************************************************************/
  var C = cipherText;
  var n = C.length/8-1;
  var K = kek;

  /****************************************************************************
   * 1) Initialize variables
   *    Set A = C[0]
   *    For i = 1 to b
   *      R[i] = C[i]
   ***************************************************************************/
  var A = C.slice(0,8);
  
  var R = [createBuffer(1)];
  for (var i = 1; i <= n; i++)
    R.push(C.slice(8*i, 8*i+8));

  /****************************************************************************
   * 2) compute intermediate values
   *    For j = 5 to 0
   *      For i = n to 1
   *        B = AES-1(K, (A^t) | R[i]) where t = n*j+i
   *        A = MSB(64, B)
   *        R[i] = LSB(64, B)
   ***************************************************************************/
  for(var j=5; j >= 0; j--) {
    for(var i=n; i >= 1; i--) {
      // turn t = n*j+i into buffer
      var str = (n*j+i).toString(16);
      if (str.length %2 !== 0)
        str = '0' + str;
      var t = createBuffer(str, 'hex');

      // B = AES-1(K, (A^t) | R[i])
      var aes = crypto.createDecipheriv(algorithm, K, '');
      aes.setAutoPadding(false);
      var B = aes.update(Buffer.concat([xor(A, t), R[i]]), null, 'hex');
      B += aes.final('hex');
      B = createBuffer(B, 'hex');

      // A = MSB(64, B)
      A = B.slice(0, 8);

      // R[i] = LSB(64, B)
      R[i] = B.slice(B.length-8);
    }
  }

  /****************************************************************************
   * 3) Output results.
   *    If A is an appropriate initial value
   *    Then
   *      For i = 1 to n
   *        P[i] = R[i]
   *    Else
   *      Return an error
   ***************************************************************************/
  
  // check A
  if (A.toString('hex').toUpperCase() === 'A6A6A6A6A6A6A6A6') {
    var result = R[1];
    for (var i = 2; i <= n; i++)
      result = Buffer.concat([result, R[i]]);
    
    return result;
  } else {
    throw new Error('decryption failed: invalid A');
  }
};

var decryptCEK = (alg, encrypted_cek, key, log) => {
  var error = null;
  var cek = null;

  try {
    var key_to_use;

    if (alg === 'RSA1_5' || alg === 'RSA-OAEP')
      key_to_use = jwkToPem(key, {private: true});
    else
      key_to_use = base64url.toBuffer(key);

    if (alg === 'RSA1_5')
      cek = crypto.privateDecrypt({ key: key_to_use, padding: constants.RSA_PKCS1_PADDING }, encrypted_cek);
    else if (alg === 'RSA-OAEP')
      cek = crypto.privateDecrypt({ key: key_to_use, padding: constants.RSA_PKCS1_OAEP_PADDING }, encrypted_cek);
    else if (alg === 'A128KW')
      cek = keyUnWrap('aes-128-ecb', encrypted_cek, key);
    else if (alg === 'A256KW')
      cek = keyUnWrap('aes-256-ecb', encrypted_cek, key);
    else
      cek = key_to_use;  // dir 
  } catch (ex) {
    error = ex;
  }

  return {'error': error, 'cek': cek};
};

var getCEK = (header, encrypted_cek, jweKeyStore, log) {
  var algKtyMapper = { 'RSA1_5': 'RSA', 'RSA-OAEP': 'RSA', 'dir': 'oct', 'A128KW': 'oct', 'A256KW': 'oct'};

  if (!header.alg)
    throw new Error('alg is missing in JWE header');
  if(['RSA1_5', 'RSA-OAEP', 'dir', 'A128KW', 'A256KW'].indexOf(header.alg) === -1)
    throw new Error('Unsupported alg in JWE header: ' + header.alg);

  var key = null;

  if (header.kid) {
    for (var i = 0; i < jweKeyStore.length; i++) {
      if (header.kid === jweKeyStore[i].kid && algMapper[header.alg] === jweKeyStore[i].kty) {
        key = jweKeyStore[i];
        log.info('found a key matching kid: ' + header.kid);
        break;
      }
    }

    if (!key)
      return { 'error': new Error('unable to find a key with kid: ' + header.kid), 'cek': null };

    return decryptCEK(header.alg, encrypted_cek, key, log);
  }

  // The header has no kid, so we try every possible key
  
};

exports.decryt = (jweString, jweKeyStore, log, callback) => {
  /****************************************************************************
   *   JWE compact format structure
   ****************************************************************************
   * BASE64URL(UTF8(JWE Protected Header)) || '.' ||
   * BASE64URL(JWE Encrypted Key) || '.' || 
   * BASE64URL(JWE Initialization Vector) || '.' || 
   * BASE64URL(JWE Ciphertext) || '.' || 
   * BASE64URL(JWE Authentication Tag)
   ***************************************************************************/
  var parts = jweString.split('.');
  var header = JSON.parse(base64url.decode(parts[0], 'binary'));
  var aad = createBuffer(parts[0]);
  var encrypted_cek = base64url.toBuffer(parts[1]);
  var iv = base64url.toBuffer(parts[2]);
  var cipherText = base64url.toBuffer(parts[3]);
  var authTag = base64url.toBuffer(parts[4]);

  log.info('In jwe.decrypt: the header is ' + JSON.stringify(header));

  /****************************************************************************
   *  cek decryption
   ***************************************************************************/
  var cek_result = getCEK(header, encrypted_cek, jweKeyStore, log);
  if (cek_result.error)
    return callback(cek_result.error);

  /****************************************************************************
   *  content decryption
   ***************************************************************************/
  var decipher = null;

  if (header.enc === 'A128GCM')
    decipher = crypto.createDecipheriv('aes-128-gcm', cek, iv);
  if (header.enc === 'A256GCM')
  	decipher = crypto.createDecipheriv('aes-256-gcm', cek, iv);
  else if (header.enc === 'A128CBC-HS256')
  	decipher = aesHmac.createDecipheriv('aes-128-cbc-hmac-sha-256', cek, iv);
  else if (header.enc === 'A256CBC-HS512')
    decipher = aesHmac.createDecipheriv('aes-256-cbc-hmac-sha-512', cek, iv);
  else
    throw new Error('unsupported enc in jwe header: ' + header.enc);

  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);
  var plainText = decipher.update(cipherText);
  decipher.final();

  return plainText.toString();
};


