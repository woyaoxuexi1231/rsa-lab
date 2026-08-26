package com.lab.rsa.v4;

import com.lab.rsa.dto.DecryptRequestV4;
import com.lab.rsa.dto.EncryptResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Base64;

/**
 * v4 加解密骨架：算法仍接近 v1（PKCS1 + AES-ECB）。
 *
 * <p>学习重点在 Controller 的 keyVersion+token，不在换更强算法。
 * {@link DecryptRequestV4#getIv()} 存在但本类<strong>不读取</strong>。
 */
@Service
@Slf4j
public class V4CryptoService {

    public DecryptResult decryptRequest(DecryptRequestV4 request, PrivateKey rsaPrivateKey) throws Exception {
        log.info("[v4] RSA 解 AES key + AES-ECB 解业务数据（iv 字段预留未使用）");

        // 即使请求里带了 iv，这里也故意不用——对照 DecryptRequestV4 的字段说明
        byte[] aesKey = rsaDecryptPkcs1(request.getEncryptedKey(), rsaPrivateKey);
        byte[] plaintextBytes = aesDecryptEcb(request.getEncryptedData(), aesKey);
        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        return new DecryptResult(aesKey, plaintext);
    }

    public EncryptResponse encryptResponse(String responsePlaintext, byte[] aesKey) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"));
        byte[] encrypted = aesCipher.doFinal(responsePlaintext.getBytes(StandardCharsets.UTF_8));

        // 复用基类 EncryptResponse；signature=null（本版不强调响应完整性）
        return new EncryptResponse(Base64.getEncoder().encodeToString(encrypted), null);
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
