var crypto = require('crypto');
const base64url = require('base64url');

var aesHmac = require('aes-cbc-hmac-sha2');

var conv = (buf) => {
  var res = [];
  for (let val of buf.values())
  	res.push(val);
  console.log(res);
};

var aes_256_gcm_encrypt = () => {
  var algorithm = 'aes-256-gcm';
  var cek = Buffer.from([177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
   212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
   234, 64, 252]);
  var iv = Buffer.from([227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]);
  var aad = Buffer.from([101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
   116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
   54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81]);
  var text = Buffer.from(  [84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
   111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
   101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
   101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
   110, 97, 116, 105, 111, 110, 46]);

  var cipher = crypto.createCipheriv(algorithm, cek, iv);
  cipher.setAAD(aad);
  var encrypted = cipher.update(text);
  cipher.final();
  var tag = cipher.getAuthTag();

  var decipher = crypto.createDecipheriv('aes-256-gcm', cek, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  var dec = decipher.update(encrypted);
  decipher.final();
};

var aes_256_gcm_decrypt = () => {
  /*
   * BASE64URL(UTF8(JWE Protected Header)) || '.' ||
   * BASE64URL(JWE Encrypted Key) || '.' || 
   * BASE64URL(JWE Initialization Vector) || '.' || 
   * BASE64URL(JWE Ciphertext) || '.' || 
   * BASE64URL(JWE Authentication Tag)
   */
  var jweString = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ';
  var parts = jweString.split('.');
  var header = JSON.parse(base64url.decode(parts[0], 'binary'));
  var aad = Buffer.from(parts[0]);
  var iv = base64url.toBuffer(parts[2]);
  var cipherText = base64url.toBuffer(parts[3]);
  var authTag = base64url.toBuffer(parts[4]);

  console.log('using header: ');
  console.log(header);

  var cek = Buffer.from([177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
   212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
   234, 64, 252]);

  var decipher = crypto.createDecipheriv('aes-256-gcm', cek, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);
  var dec = decipher.update(cipherText);
  decipher.final();
  console.log(dec.toString());
};

var aes_128_cbc_hmac_sha_256_decrypt = () => {
  var jweString = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.9hH0vgRfYgPnAHOd8stkvw';


  var parts = jweString.split('.');
  var header = JSON.parse(base64url.decode(parts[0], 'binary'));
  var aad = Buffer.from(parts[0]);
  var iv = base64url.toBuffer(parts[2]);
  var cipherText = base64url.toBuffer(parts[3]);
  var authTag = base64url.toBuffer(parts[4]); 

  console.log('using header: ');
  console.log(header);

  var cek = Buffer.from([4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
   206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
   44, 207]);

  var decipher = aesHmac.createDecipheriv('aes-128-cbc-hmac-sha-256', cek, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);
  var dec = decipher.update(cipherText);
  decipher.final();
  conv(dec);
};

aes_128_cbc_hmac_sha_256_decrypt();


