/* ============================================================
   浏览器端混合加密（node-forge）— 按版本区分算法细节
   ============================================================ */
import forge from 'node-forge'

function rsaEncryptAesKey (publicKeyPem, aesKey) {
  const publicKey = forge.pki.publicKeyFromPem(publicKeyPem)
  return forge.util.encode64(publicKey.encrypt(aesKey))
}

function aesEncryptEcb (aesKey, plaintext) {
  const cipher = forge.cipher.createCipher('AES-ECB', aesKey)
  cipher.start()
  cipher.update(forge.util.createBuffer(plaintext, 'utf8'))
  cipher.finish()
  return forge.util.encode64(cipher.output.getBytes())
}

function aesDecryptEcb (aesKey, encryptedDataBase64) {
  const decipher = forge.cipher.createDecipher('AES-ECB', aesKey)
  decipher.start()
  decipher.update(forge.util.createBuffer(forge.util.decode64(encryptedDataBase64)))
  if (!decipher.finish()) throw new Error('AES-ECB 解密失败')
  return forge.util.decodeUtf8(decipher.output.getBytes())
}

function aesEncryptCbc (aesKey, plaintext, iv) {
  const cipher = forge.cipher.createCipher('AES-CBC', aesKey)
  cipher.start({ iv })
  cipher.update(forge.util.createBuffer(plaintext, 'utf8'))
  cipher.finish()
  return {
    ivBase64: forge.util.encode64(iv),
    encryptedDataBase64: forge.util.encode64(cipher.output.getBytes())
  }
}

function aesDecryptCbc (aesKey, encryptedDataBase64, ivBase64) {
  const decipher = forge.cipher.createDecipher('AES-CBC', aesKey)
  decipher.start({ iv: forge.util.decode64(ivBase64) })
  decipher.update(forge.util.createBuffer(forge.util.decode64(encryptedDataBase64)))
  if (!decipher.finish()) throw new Error('AES-CBC 解密失败')
  return forge.util.decodeUtf8(decipher.output.getBytes())
}

function verifySha256WithRsa (publicKeyPem, messageBytes, signatureBase64) {
  const publicKey = forge.pki.publicKeyFromPem(publicKeyPem)
  const md = forge.md.sha256.create()
  md.update(messageBytes, 'raw')
  return publicKey.verify(md.digest().getBytes(), forge.util.decode64(signatureBase64))
}

/** v1：RSA + AES-ECB，无签名 */
export function buildV1Payload (publicKeyPem, plaintext) {
  const aesKey = forge.random.getBytesSync(16)
  return {
    aesKeyBytes: aesKey,
    payload: {
      encryptedKey: rsaEncryptAesKey(publicKeyPem, aesKey),
      encryptedData: aesEncryptEcb(aesKey, plaintext)
    }
  }
}

export function decryptV1Response (response, aesKeyBytes) {
  return aesDecryptEcb(aesKeyBytes, response.encryptedData)
}

/** v2：响应 SHA256withRSA 签密文 */
export function buildV2Payload (publicKeyPem, plaintext) {
  return buildV1Payload(publicKeyPem, plaintext)
}

export function decryptV2Response (response, aesKeyBytes, publicKeyPem) {
  const ct = forge.util.decode64(response.encryptedData)
  if (!verifySha256WithRsa(publicKeyPem, ct, response.signature)) {
    throw new Error('响应签名校验失败')
  }
  return aesDecryptEcb(aesKeyBytes, response.encryptedData)
}

/** v3：AES-CBC + 签 (iv||密文) */
export function buildV3Payload (publicKeyPem, plaintext) {
  const aesKey = forge.random.getBytesSync(16)
  const iv = forge.random.getBytesSync(16)
  const { ivBase64, encryptedDataBase64 } = aesEncryptCbc(aesKey, plaintext, iv)
  return {
    aesKeyBytes: aesKey,
    payload: {
      encryptedKey: rsaEncryptAesKey(publicKeyPem, aesKey),
      iv: ivBase64,
      encryptedData: encryptedDataBase64
    }
  }
}

export function decryptV3Response (response, aesKeyBytes, publicKeyPem) {
  const ivBytes = forge.util.decode64(response.iv)
  const ct = forge.util.decode64(response.encryptedData)
  if (!verifySha256WithRsa(publicKeyPem, ivBytes + ct, response.signature)) {
    throw new Error('响应签名校验失败（iv||密文）')
  }
  return aesDecryptCbc(aesKeyBytes, response.encryptedData, response.iv)
}

/** v4：在 v1 载荷上增加 keyVersion + token */
export function buildV4Payload (publicKeyPem, plaintext, keyInfo) {
  const { aesKeyBytes, payload } = buildV1Payload(publicKeyPem, plaintext)
  return {
    aesKeyBytes,
    payload: {
      keyVersion: keyInfo.keyVersion,
      token: keyInfo.token,
      ...payload
    }
  }
}

export function decryptV4Response (response, aesKeyBytes) {
  return aesDecryptEcb(aesKeyBytes, response.encryptedData)
}

/** v5：timestamp + nonce + HMAC */
export function buildV5Payload (publicKeyPem, plaintext, keyInfo) {
  const aesKey = forge.random.getBytesSync(16)
  const timestamp = Date.now()
  const nonce = forge.util.bytesToHex(forge.random.getBytesSync(16))
  const encryptedData = aesEncryptEcb(aesKey, plaintext)

  const signRaw = [keyInfo.keyVersion, String(timestamp), nonce, encryptedData].join('|')
  const hmac = forge.hmac.create()
  hmac.start('sha256', aesKey)
  hmac.update(signRaw)
  const requestSignature = forge.util.encode64(hmac.digest().getBytes())

  return {
    aesKeyBytes: aesKey,
    payload: {
      keyVersion: keyInfo.keyVersion,
      token: keyInfo.token,
      timestamp,
      nonce,
      encryptedKey: rsaEncryptAesKey(publicKeyPem, aesKey),
      encryptedData,
      requestSignature
    }
  }
}

export function decryptV5Response (response, aesKeyBytes) {
  return aesDecryptEcb(aesKeyBytes, response.encryptedData)
}
