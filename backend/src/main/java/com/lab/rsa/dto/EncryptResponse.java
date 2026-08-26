package com.lab.rsa.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 响应体基类 —— <b>v1 / v2 / v4 / v5</b>。
 *
 * <pre>
 * EncryptResponse                 // encryptedData + signature
 *   └─ EncryptResponseV3          // + iv（CBC 响应需要把 IV 回传）
 * </pre>
 *
 * <p>v1/v4/v5 的 {@code signature} 可为 null；v2 起响应方向才真正填签名。
 */
@Data
@NoArgsConstructor
public class EncryptResponse {

    /** AES 加密后的响应明文（Base64） */
    private String encryptedData;

    /**
     * 响应完整性签名（Base64）。
     * v2：对密文字节做 SHA256withRSA；v3：对 iv||密文；其它版本常为 null。
     */
    private String signature;

    public EncryptResponse(String encryptedData, String signature) {
        this.encryptedData = encryptedData;
        this.signature = signature;
    }
}
