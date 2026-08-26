package com.lab.rsa.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * <b>v4</b> 请求：版本绑定 + 预留 {@code iv}。
 *
 * <p>{@code iv} 出现在协议里，但当前 CryptoService <strong>尚未读取</strong>——
 * 这是刻意保留的「骨架痕迹」，提醒字段声明 ≠ 实现已接通。
 */
@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class DecryptRequestV4 extends VersionedDecryptRequest {

    /** 预留：规划接 CBC/GCM 时使用；v4 实现忽略此字段 */
    private String iv;

    public DecryptRequestV4(String keyVersion, String token, String encryptedKey,
                            String iv, String encryptedData) {
        super(keyVersion, token, encryptedKey, encryptedData);
        this.iv = iv;
    }
}
