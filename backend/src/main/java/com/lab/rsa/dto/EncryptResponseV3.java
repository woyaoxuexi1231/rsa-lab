package com.lab.rsa.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * <b>v3</b> 响应：在基类上增加 {@code iv}。
 *
 * <p>服务端每次加密回包都生成<strong>新的</strong>随机 IV（与请求 iv 无关），
 * 并与密文一起参与签名。
 */
@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class EncryptResponseV3 extends EncryptResponse {

    /** 本次响应加密使用的 IV（Base64） */
    private String iv;

    public EncryptResponseV3(String iv, String encryptedData, String signature) {
        super(encryptedData, signature);
        this.iv = iv;
    }
}
