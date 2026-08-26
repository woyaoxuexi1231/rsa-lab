package com.lab.rsa.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * <b>v4</b> 公钥响应：增加版本号与绑定 token。
 *
 * <p>前端后续 /secure/echo 必须原样回传这两项，不能自己编版本号。
 */
@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class KeyResponseV4 extends KeyResponse {

    /** 当前下发的密钥版本，如 "2" */
    private String keyVersion;

    /** 与 version+fingerprint 绑定的短时 token */
    private String token;

    public KeyResponseV4(String keyVersion, String publicKey, String algorithm, String token) {
        super(publicKey, algorithm);
        this.keyVersion = keyVersion;
        this.token = token;
    }
}
