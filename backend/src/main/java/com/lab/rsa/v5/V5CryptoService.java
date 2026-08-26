package com.lab.rsa.v5;

import com.lab.rsa.dto.DecryptRequestV5;
import com.lab.rsa.dto.EncryptResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Base64;

/**
 * v5：用 HMAC 保护请求关键字段；AES key 作 HMAC 密钥（仅双方可见）。
 *
 * <p>签名原文：{@code keyVersion|timestamp|nonce|encryptedData} —— 前后端必须完全一致。
 */
@Service
@Slf4j
public class V5CryptoService {

    /** 先解 AES key：后续验签与解密都依赖它 */
    public byte[] decryptAesKey(DecryptRequestV5 request, PrivateKey rsaPrivateKey) throws Exception {
        // 与 v1 相同：RSA 只负责「递钥匙」
        return rsaDecryptPkcs1(request.getEncryptedKey(), rsaPrivateKey);
    }

    /**
     * 重算 HMAC，与 {@code requestSignature} 比较。
     * 改 timestamp/nonce/密文/keyVersion 任一字段都会失败。
     */
    public boolean verifyRequestSignature(DecryptRequestV5 request, byte[] aesKey) throws Exception {
        // 拼接待签字符串：分隔符与字段顺序是协议的一部分，不能随便改
        String signRaw = buildSignRaw(
                request.getKeyVersion(),
                request.getTimestamp(),
                request.getNonce(),
                request.getEncryptedData()
        );
        String expected = hmacSha256Base64(aesKey, signRaw);

        // 常量时间比较在生产更稳妥；教学 Demo 用 equals 即可
        return expected.equals(request.getRequestSignature());
    }

    /** 验签通过后再解密——先确认「没被改」，再碰业务数据 */
    public DecryptResult decryptPayload(DecryptRequestV5 request, byte[] aesKey) throws Exception {
        log.info("[v5] HMAC 验签后 AES-ECB 解密业务数据");
        byte[] plaintextBytes = aesDecryptEcb(request.getEncryptedData(), aesKey);
        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        return new DecryptResult(aesKey, plaintext);
    }

    public EncryptResponse encryptResponse(String responsePlaintext, byte[] aesKey) throws Exception {
        // 本版重点在请求防重放，响应仍不签名
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"));
        byte[] encrypted = aesCipher.doFinal(responsePlaintext.getBytes(StandardCharsets.UTF_8));
        return new EncryptResponse(Base64.getEncoder().encodeToString(encrypted), null);
    }

    public record DecryptResult(byte[] aesKey, String plaintext) {
    }

    /**
     * 构造 HMAC 输入。timestamp 用 Long 的十进制 toString；null 当空串，避免 NPE 掩盖协议错误。
     */
    public static String buildSignRaw(String keyVersion, Long timestamp, String nonce, String encryptedData) {
        return nullToEmpty(keyVersion)
                + "|"
                + (timestamp == null ? "" : timestamp)
                + "|"
                + nullToEmpty(nonce)
                + "|"
                + nullToEmpty(encryptedData);
    }

    private static byte[] rsaDecryptPkcs1(String encryptedKeyB64, PrivateKey privateKey) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKey = rsa.doFinal(Base64.getDecoder().decode(encryptedKeyB64));
        if (aesKey.length != 16 && aesKey.length != 24 && aesKey.length != 32) {
            throw new IllegalArgumentException("Invalid AES key length: " + aesKey.length);
        }
        return aesKey;
    }

    private static byte[] aesDecryptEcb(String encryptedDataB64, byte[] aesKey) throws Exception {
        Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"));
        return aes.doFinal(Base64.getDecoder().decode(encryptedDataB64));
    }

    /** HMAC-SHA256：消息鉴别码，不是加密；输出再 Base64 便于放进 JSON */
    private static String hmacSha256Base64(byte[] aesKey, String content) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        // 密钥材料 = AES key 原始字节（客户端 forge 侧用同一把）
        mac.init(new SecretKeySpec(aesKey, "HmacSHA256"));
        byte[] out = mac.doFinal(content.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(out);
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
