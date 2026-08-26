package com.lab.rsa.v1;

import com.lab.rsa.dto.DecryptRequest;
import com.lab.rsa.dto.EncryptResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Base64;

/**
 * v1 加解密核心：混合加密（Hybrid Encryption）。
 *
 * <h3>为什么不全用 RSA？</h3>
 * RSA 慢，且一次能加密的明文长度受密钥限制。业界标准：
 * AES 加密业务明文；RSA 只加密那把短 AES key。
 *
 * <h3>v1 故意省略</h3>
 * 无响应签名（→v2）；AES-ECB 有模式泄露（→v3）。先跑通数据流再加固。
 */
@Service
@Slf4j
public class V1CryptoService {

    /**
     * 解密客户端请求。
     *
     * @return AES key + 明文；AES key 留给加密响应复用，避免再协商密钥
     */
    public DecryptResult decryptRequest(DecryptRequest request, PrivateKey rsaPrivateKey) throws Exception {
        log.info("[v1] RSA 解 AES key + AES-ECB 解业务数据");

        // Step1：只有服务端持有私钥，才能从 encryptedKey 还原出 AES key
        byte[] aesKey = rsaDecryptPkcs1(request.getEncryptedKey(), rsaPrivateKey);

        // Step2：用刚解出的 AES key 解开业务密文
        byte[] plaintextBytes = aesDecryptEcb(request.getEncryptedData(), aesKey);
        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);

        // 生产不要打明文；此处仅方便课堂对照
        log.debug("[v1] 明文（仅学习）: {}", plaintext);
        return new DecryptResult(aesKey, plaintext);
    }

    /**
     * 用同一把 AES key 加密响应。
     * signature 固定 null：v1 不提供完整性，前端无法发现密文是否被改。
     */
    public EncryptResponse encryptResponse(String responsePlaintext, byte[] aesKey) throws Exception {
        // 与请求侧同一算法，客户端才能用手里的 aesKey 解回包
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"));
        byte[] encrypted = aesCipher.doFinal(responsePlaintext.getBytes(StandardCharsets.UTF_8));

        // 第二个参数 null = 明确告诉调用方「本版无签名」
        return new EncryptResponse(Base64.getEncoder().encodeToString(encrypted), null);
    }

    /** 保留 aesKey：回包继续用对称加密，不必再走 RSA */
    public record DecryptResult(byte[] aesKey, String plaintext) {
    }

    /**
     * RSA/ECB/PKCS1Padding：JCA 历史命名，实际是 RSA + PKCS#1 v1.5，不是 AES-ECB。
     * 生产更推荐 OAEP，本实验室后续再升级。
     */
    private static byte[] rsaDecryptPkcs1(String encryptedKeyB64, PrivateKey privateKey) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.DECRYPT_MODE, privateKey);

        // HTTP/JSON 里传的是 Base64 文本，先还原成原始密文字节再交给 Cipher
        byte[] aesKey = rsa.doFinal(Base64.getDecoder().decode(encryptedKeyB64));

        // AES-128/192/256 → 16/24/32 字节；其它长度说明解出来的不是合法 AES key
        if (aesKey.length != 16 && aesKey.length != 24 && aesKey.length != 32) {
            throw new IllegalArgumentException("Invalid AES key length: " + aesKey.length);
        }
        return aesKey;
    }

    /**
     * AES-ECB：每 16 字节独立加密，相同明文块 → 相同密文块（会泄露模式）。
     * v1 用最少概念跑通；v3 换成 CBC。
     */
    private static byte[] aesDecryptEcb(String encryptedDataB64, byte[] aesKey) throws Exception {
        Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"));
        return aes.doFinal(Base64.getDecoder().decode(encryptedDataB64));
    }
}
