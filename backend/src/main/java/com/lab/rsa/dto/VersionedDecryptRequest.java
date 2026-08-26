package com.lab.rsa.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * 带「密钥版本绑定」的请求中间层 —— <b>v4 / v5</b> 共用。
 *
 * <p>相对 v1：多了 {@code keyVersion} + {@code token}。
 * 单独抽这一层，是为了让你看清「版本保护」与「防重放」是两次独立升级。
 */
@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public abstract class VersionedDecryptRequest extends DecryptRequest {

    /** 客户端声称使用的密钥版本；不可单独信任，必须配合 token 校验 */
    private String keyVersion;

    /** 服务端在 GET /key 时签发的短时凭证，绑定 version + fingerprint + 过期时间 */
    private String token;

    protected VersionedDecryptRequest(String keyVersion, String token,
                                      String encryptedKey, String encryptedData) {
        super(encryptedKey, encryptedData);
        this.keyVersion = keyVersion;
        this.token = token;
    }
}
