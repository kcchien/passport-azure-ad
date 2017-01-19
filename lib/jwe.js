
'use strict';

var crypto = require('crypto');
var constants = require('constants');
const base64url = require('base64url');

var aadutils = require('./aadutils');
var aesHmac = require('aes-cbc-hmac-sha2');
var jwkToPem = require('jwk-to-pem');

var conv = (buf) => {
  var res = '';
  for (let val of buf.values())
  	res += val + ',';
  console.log(res);
};

exports.decryt = (jweString, key) => {
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
  var aad;
  if (process.version >= 'v6') 
    aad = Buffer.from(parts[0]);
  else
    aad = new Buffer(parts[0]);
  var encrypted_cek = base64url.toBuffer(parts[1]);
  var iv = base64url.toBuffer(parts[2]);
  var cipherText = base64url.toBuffer(parts[3]);
  var authTag = base64url.toBuffer(parts[4]);

  /****************************************************************************
   *  cek decryption
   ***************************************************************************/
  var cek = null;
  var key_to_use = null;

  if (header.alg === 'RSA1_5' || header.alg === 'RSA-OAEP')
  	key_to_use = jwkToPem(key, {private: true});
  else
  	key_to_use = Buffer.from(key);

  if (header.alg === 'RSA1_5')
  	cek = crypto.privateDecrypt({ key: key_to_use, padding: constants.RSA_PKCS1_PADDING }, encrypted_cek);
  else if (header.alg === 'RSA-OAEP')
  	cek = crypto.privateDecrypt({ key: key_to_use, padding: constants.RSA_PKCS1_OAEP_PADDING }, encrypted_cek);
  else if (header.alg === 'dir')
  	cek = key_to_use;
  else
  	return null;

  /****************************************************************************
   *  content decryption
   ***************************************************************************/
  var decipher = null;

  if (header.enc === 'A256GCM')
  	decipher = crypto.createDecipheriv('aes-256-gcm', cek, iv);
  else if (header.enc === 'A128CBC-HS256')
  	decipher = aesHmac.createDecipheriv('aes-128-cbc-hmac-sha-256', cek, iv);
  else
  	return null;

  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);
  var plainText = decipher.update(cipherText);
  decipher.final();

  return plainText.toString();
};

function xor(a, b) {
  var la = a.length;
  var lb = b.length;
  var c1, c2;
  if (la > lb) {
    c1 = a; c2 =b;
  } else {
    c2 = a; c1 = b;
  }
  var c = Buffer.from(c1);
  for (var i = 1; i <= c2.length; i++)
    c[c1.length-i] = c[c1.length-i] ^ c2[c2.length-i];
  return c;
}

var keyWrap = (algorithm, contentKey, kek) => {
  var n = contentKey.length/8;
  var A = Buffer.from("A6A6A6A6A6A6A6A6", "hex");
  
  var R = [Buffer.alloc(1)];
  for (var i = 1; i <= n; i++)
    R.push(contentKey.slice(8*i-8, 8*i));

  for(var j=0; j<= 5; j++) {
    for(var i=1; i<= n; i++) {
      var aes = crypto.createCipheriv(algorithm, kek, '');
      aes.setAutoPadding(false);
      var B = aes.update(Buffer.concat([A, R[i]]), null, 'hex');
      B = B + aes.final('hex');
      B = Buffer.from(B, 'hex');

      var str = (n*j+i).toString(16);
      if (str.length %2 !== 0)
        str = '0' + str;
      var t = Buffer.from(str, 'hex');

      A = xor(B.slice(0, 8), t);
      R[i] = B.slice(B.length-8);
    }
  }

  console.log(A.toString('hex'));
  var result = Buffer.from(A);
  for (var i = 1; i <= n; i++)
    result = Buffer.concat([result, R[i]]);
  console.log(result.toString('hex'));
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
  
  var R = [Buffer.alloc(1)];
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
      var t = Buffer.from(str, 'hex');

      // B = AES-1(K, (A^t) | R[i])
      var aes = crypto.createDecipheriv(algorithm, K, '');
      aes.setAutoPadding(false);
      var B = aes.update(Buffer.concat([xor(A, t), R[i]]), null, 'hex');
      B += aes.final('hex');
      B = Buffer.from(B, 'hex');

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
    console.log('good');
    var result = R[1];
    for (var i = 2; i <= n; i++)
      result = Buffer.concat([result, R[i]]);
    console.log(result.toString('hex'));
  } else
    console.log('bad');
};

/******************************************************************************/

// var kek = Buffer.from('000102030405060708090A0B0C0D0E0F', 'hex');
// var cek = Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex');
// var cipherText = Buffer.from('1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5', 'hex');

// var kek = base64url.toBuffer('GawgguFyGrWKav7AX4VKUg');
// var cek = Buffer.from([4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
//    206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
//    44, 207]);
// console.log(base64url.encode(cek));
// var cipherText = Buffer.from('e8a07bd3b74cf584c8807b4bbed81643c98ac1ba095b7a1ff65a1c8b39034c7cc10b6225ad3d6839', 'hex');

// keyWrap('aes-128-ecb', cek, kek);
// keyUnWrap('aes-128-ecb', cipherText, kek);

/******************************************************************************/

var kek = Buffer.from('000102030405060708090A0B0C0D0E0F1011121314151617', 'hex');
var cek = Buffer.from('00112233445566778899AABBCCDDEEFF0001020304050607', 'hex');
var cipherText = Buffer.from('031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2', 'hex');

keyWrap('aes-192-ecb', cek, kek);
keyUnWrap('aes-192-ecb', cipherText, kek);

