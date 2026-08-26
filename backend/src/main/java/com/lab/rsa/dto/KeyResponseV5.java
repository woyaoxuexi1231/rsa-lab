package com.lab.rsa.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * <b>v5</b> 公钥响应：在 v4 上再告诉前端防重放时间窗。
 */
@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class KeyResponseV5 extends KeyResponseV4 {

    /** 允许的 |客户端时间 - 服务端时间| 上限（毫秒），与 NonceService 配置一致 */
    private Long replayWindowMs;

    public KeyResponseV5(String keyVersion, String publicKey, String algorithm,
                         String token, Long replayWindowMs) {
        super(keyVersion, publicKey, algorithm, token);
        this.replayWindowMs = replayWindowMs;
    }
}
