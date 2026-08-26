package com.lab.rsa.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 公钥下发响应基类 —— <b>v1 / v2 / v3</b>。
 *
 * <pre>
 * KeyResponse                     // publicKey + algorithm
 *   └─ KeyResponseV4              // + keyVersion + token
 *        └─ KeyResponseV5         // + replayWindowMs
 * </pre>
 */
@Data
@NoArgsConstructor
public class KeyResponse {

    /** PEM 格式 RSA 公钥，前端用 node-forge 解析 */
    private String publicKey;

    /** 给人读的算法/版本说明（非严格 JCA 名） */
    private String algorithm;

    public KeyResponse(String publicKey, String algorithm) {
        this.publicKey = publicKey;
        this.algorithm = algorithm;
    }
}
