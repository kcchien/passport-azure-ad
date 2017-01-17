
'use strict';

var crypto = require('crypto');
var constants = require('constants');
const base64url = require('base64url');

var aadutils = require('./aadutils');
var aesHmac = require('aes-cbc-hmac-sha2');
var jwkToPem = require('jwk-to-pem');

var conv = (buf) => {
  var res = [];
  for (let val of buf.values())
  	res.push(val);
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
  var aad = Buffer.from(parts[0]);
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