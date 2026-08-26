package com.lab.rsa.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 请求体基类 —— 对应 <b>v1 / v2</b>。
 *
 * <pre>
 * DecryptRequest                          // v1/v2：encryptedKey + encryptedData
 *   ├─ DecryptRequestV3                   // + iv
 *   └─ VersionedDecryptRequest            // + keyVersion + token
 *        ├─ DecryptRequestV4              // + iv（骨架预留）
 *        └─ DecryptRequestV5              // + timestamp + nonce + requestSignature
 * </pre>
 *
 * <p>看继承树就能回答：「从上一版到这一版，协议多带了哪些字段？」
 */
@Data
@NoArgsConstructor
public class DecryptRequest {

    /**
     * RSA 公钥加密后的 AES key（Base64）。
     * 服务端用 RSA 私钥解开后，才能继续解业务密文。
     */
    private String encryptedKey;

    /**
     * AES 加密后的业务数据（Base64）。
     * v1/v2/v4/v5 用 ECB；v3 用 CBC（还需要子类里的 iv）。
     */
    private String encryptedData;

    public DecryptRequest(String encryptedKey, String encryptedData) {
        this.encryptedKey = encryptedKey;
        this.encryptedData = encryptedData;
    }
}
