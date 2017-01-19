
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

var printR = (t, A, arr, B) => {
  if (t !== 1)
    return;
  console.log(' after step ' + t + ' #################');
  console.log('A = ');
  console.log(A.toString('hex'));
  console.log('R1 = ');
  console.log(arr[1].toString('hex'));
  console.log('R2 = ');
  console.log(arr[2].toString('hex'));
  if (B) {
    console.log('B = ');
    console.log(B.toString('hex'));
  }
}

var printRBefore = (t, A, arr, B) => {
    if (t !== 1)
    return;
  console.log(' before step ' + t + ' #################');
  console.log('A = ');
  console.log(A.toString('hex'));
  console.log('R1 = ');
  console.log(arr[1].toString('hex'));
  console.log('R2 = ');
  console.log(arr[2].toString('hex'));
  if (B) {
    console.log('B = ');
    console.log(B.toString('hex'));
  }
}

var test1 = {contentKey: '00112233445566778899AABBCCDDEEFF', kek: '000102030405060708090A0B0C0D0E0F', dataBits: 128, kekBits: 128,
  cipherText: '1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5'  
};
var test2 = {contentKey: '00112233445566778899AABBCCDDEEFF', kek: '000102030405060708090A0B0C0D0E0F1011121314151617', dataBits: 128, kekBits: 192};

var keyWrap = (test) => {
  var contentKey = Buffer.from(test.contentKey, 'hex');
  var n = contentKey.length/8;
  var kek = Buffer.from(test.kek, 'hex');
  var A = Buffer.from("A6A6A6A6A6A6A6A6", "hex");
  
  var R = [Buffer.alloc(1)];
  for (var i = 1; i <= n; i++)
    R.push(contentKey.slice(8*i-8, 8*i));

  for(var j=0; j<= 5; j++) {
    for(var i=1; i<= n; i++) {
      printRBefore(n*j+i, A, R);
      var aes = crypto.createCipheriv("aes-" + test.kekBits + "-ecb", kek, '');
      var B = aes.update(Buffer.concat([A, R[i]]));
      console.log('in update: ' + B.toString('hex'));
      console.log('in final: ' + aes.final('hex'));
      B = Buffer.from(B, 'hex');

      var str = (n*j+i).toString(16);
      if (str.length %2 !== 0)
        str = '0' + str;
      var t = Buffer.from(str, 'hex');

      A = xor(B.slice(0, 8), t);
      R[i] = B.slice(B.length-8);
      printR(n*j+i, A, R);
    }
  }

  console.log(A.toString('hex'));
  console.log(R[1].toString('hex'));
  console.log(R[2].toString('hex'));
}

//keyWrap(test1);

var keyWrap2 = () => {
  var contentKey = Buffer.from([4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
   206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
   44, 207]);
  var n = contentKey.length/8;
  var kek = base64url.toBuffer("GawgguFyGrWKav7AX4VKUg");
  var A = Buffer.from("A6A6A6A6A6A6A6A6", "hex");
  
  var R = [Buffer.alloc(1)];
  for (var i = 1; i <= n; i++)
    R.push(contentKey.slice(8*i-8, 8*i));

  for(var j=0; j<= 5; j++) {
    for(var i=1; i<= n; i++) {
      //printRBefore(n*j+i, A, R);
      var aes = crypto.createCipheriv("aes-128-ecb", kek, '');
      var B = aes.update(Buffer.concat([A, R[i]]));
      console.log('in update: ' + B.toString('hex'));
      console.log('in final: ' + aes.final('hex'));
      B = Buffer.from(B, 'hex');

      var str = (n*j+i).toString(16);
      if (str.length %2 !== 0)
        str = '0' + str;
      var t = Buffer.from(str, 'hex');

      A = xor(B.slice(0, 8), t);
      R[i] = B.slice(B.length-8);
      //printR(n*j+i, A, R);
    }
  }

  console.log(A.toString('hex'));
  conv(R[4]);
}

keyWrap2();

var keyUnWrap = (test) => {
  var C = Buffer.from(test.cipherText, 'hex');
  var n = C.length/8-1;
  var K = Buffer.from(test.kek, 'hex');
  var A = C.slice(0,8);
  
  var R = [Buffer.alloc(1)];
  for (var i = 1; i <= n; i++)
    R.push(C.slice(8*i, 8*i+8));

  for(var j=5; j >= 0; j--) {
    for(var i=n; i >= 1; i--) {
      printRBefore(n*j+i, A, R);

      var str = (n*j+i).toString(16);
      if (str.length %2 !== 0)
        str = '0' + str;
      var t = Buffer.from(str, 'hex');

      var aes = crypto.createDecipheriv("aes-128-ecb", K, '');
      var at = xor(A, t);
      var atri = Buffer.concat([at, R[i]]);
      var B = aes.update(atri, null, 'hex');
      B = aes.final();

      console.log('R[i] = ' + R[i].toString('hex'));

      A = B.slice(0, 8);
      R[i] = B.slice(B.length-8);
      printR(n*j+i, A, R);
    }
  }

  console.log(A.toString('hex'));
  console.log(R[1].toString('hex'));
}

//keyUnWrap(test1);

var tmp = () => {
  var kek = Buffer.from('000102030405060708090A0B0C0D0E0F', 'hex');
  var contentKey = Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex');
  var aes = crypto.createCipheriv("aes-128-ecb", kek, '');
  var B = aes.update(contentKey, null, 'hex');
  B += aes.final('hex');
  console.log('encrypted: ' + B);
  var daes = crypto.createDecipheriv("aes-128-ecb", kek, '');
  var cc = daes.update(Buffer.from(B, 'hex'));
  console.log('decrypted: ' + cc.toString('hex'));  
}

tmp();