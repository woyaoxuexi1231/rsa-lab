package com.lab.rsa.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * <b>v5</b> 请求：在版本绑定之上增加防重放三件套。
 *
 * <p>相对 {@link VersionedDecryptRequest} 多了：
 * {@code timestamp}、{@code nonce}、{@code requestSignature}。
 * 故意不继承 v4 的 {@code iv}，因为本版教学重点不在 CBC。
 */
@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class DecryptRequestV5 extends VersionedDecryptRequest {

    /** 客户端发送时刻（epoch millis）；须落在服务端时间窗内 */
    private Long timestamp;

    /** 每次请求唯一的随机串；服务端只允许成功消费一次 */
    private String nonce;

    /**
     * HMAC-SHA256(AES key, keyVersion|timestamp|nonce|encryptedData) 的 Base64。
     * 改其中任一字段都会导致验签失败。
     */
    private String requestSignature;

    public DecryptRequestV5(String keyVersion, String token, Long timestamp, String nonce,
                            String encryptedKey, String encryptedData, String requestSignature) {
        super(keyVersion, token, encryptedKey, encryptedData);
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.requestSignature = requestSignature;
    }
}
