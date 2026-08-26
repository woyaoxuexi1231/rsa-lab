package com.lab.rsa.v2;

import com.lab.rsa.dto.DecryptRequest;
import com.lab.rsa.dto.EncryptResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

/**
 * v2：给<strong>响应密文</strong>做 SHA256withRSA 签名。
 *
 * <h3>v1 的漏洞</h3>
 * 攻击者可改响应 {@code encryptedData}；客户端解密得到乱码却不知情。
 *
 * <h3>修法</h3>
 * 服务端对密文字节签名；客户端公钥先验签再解密。
 * 请求方向仍未签名（→v5 HMAC）；仍用 ECB（→v3 CBC）。
 */
@Service
@Slf4j
public class V2CryptoService {

    /** 解密与 v1 相同：DTO 也复用基类 {@link DecryptRequest} */
    public DecryptResult decryptRequest(DecryptRequest request, PrivateKey rsaPrivateKey) throws Exception {
        log.info("[v2] RSA 解 AES key + AES-ECB 解业务数据");

        byte[] aesKey = rsaDecryptPkcs1(request.getEncryptedKey(), rsaPrivateKey);
        byte[] plaintextBytes = aesDecryptEcb(request.getEncryptedData(), aesKey);
        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        return new DecryptResult(aesKey, plaintext);
    }

    /**
     * 加密响应并签名。
     * 签名对象是密文<strong>原始字节</strong>，不是 Base64 字符串——前后端必须约定一致。
     */
    public EncryptResponse encryptResponse(String responsePlaintext, byte[] aesKey, PrivateKey signingKey) throws Exception {
        log.info("[v2] AES-ECB 加密响应 + SHA256withRSA 签密文");

        // --- 对称加密回包（与 v1 相同）---
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"));
        byte[] encrypted = aesCipher.doFinal(responsePlaintext.getBytes(StandardCharsets.UTF_8));

        // --- v2 新增：对密文字节做摘要并 RSA 签名 ---
        // SHA256withRSA = SHA-256(message) 再 RSA 私钥签哈希
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(signingKey);   // 告诉引擎：用这把私钥签
        signature.update(encrypted);      // 喂入「要保护的内容」= 密文字节
        byte[] sig = signature.sign();    // 得到签名字节

        // JSON 只能安全传文本，所以密文和签名都 Base64；验签时前端必须先 decode 再 verify
        return new EncryptResponse(
                Base64.getEncoder().encodeToString(encrypted),
                Base64.getEncoder().encodeToString(sig)
        );
    }

    public record DecryptResult(byte[] aesKey, String plaintext) {
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
}
