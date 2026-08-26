package com.lab.rsa.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * <b>v3</b> 请求：在基类上增加 {@code iv}。
 *
 * <p>AES-CBC 解密第一个块必须异或 IV；没有它 Cipher 无法正确还原明文。
 */
@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class DecryptRequestV3 extends DecryptRequest {

    /** 客户端加密时生成的 16 字节随机 IV（Base64）；不保密，但完整性靠响应侧签名保护 */
    private String iv;

    public DecryptRequestV3(String encryptedKey, String iv, String encryptedData) {
        super(encryptedKey, encryptedData);
        this.iv = iv;
    }
}
