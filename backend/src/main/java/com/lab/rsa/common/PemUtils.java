package com.lab.rsa.common;

import java.security.PublicKey;
import java.util.Base64;

/**
 * 把 Java {@link PublicKey} 转成 PEM 文本，方便前端（node-forge）直接解析。
 *
 * <p>为什么要 PEM？浏览器端拿不到 Java 的 Key 对象，只能拿到一段可复制的文本。
 * PEM 是行业常用格式：头尾标记 + Base64 编码的 DER 字节，前端用
 * {@code forge.pki.publicKeyFromPem(...)} 即可还原公钥。
 */
public final class PemUtils {
    private PemUtils() {
    }

    /**
     * @param publicKey X.509 SubjectPublicKeyInfo（RSA 公钥）
     * @return 带 BEGIN/END 标记的 PEM 字符串；每行约 64 字符，符合常见 PEM 排版习惯
     */
    public static String toPublicKeyPem(PublicKey publicKey) {
        String base64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        // 每 64 字符插入换行：许多 PEM 解析器能容忍无换行，但换行后更易人工阅读与调试
        return "-----BEGIN PUBLIC KEY-----\n" +
                base64.replaceAll("(.{64})", "$1\n") +
                "\n-----END PUBLIC KEY-----";
    }
}
