package com.lab.rsa.v3;

import com.lab.rsa.dto.DecryptRequestV3;
import com.lab.rsa.dto.EncryptResponseV3;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;

/**
 * v3：AES-CBC + 随机 IV；响应签名覆盖 {@code iv || ciphertext}。
 *
 * <h3>为何离开 ECB？</h3>
 * ECB 相同明文块→相同密文块。CBC 用 IV/上一密文块异或后再加密，打破这种模式。
 *
 * <h3>IV</h3>
 * 不保密但须随机、每次不同；被篡改会破坏首块明文，故签名要带上 IV。
 */
@Service
@Slf4j
public class V3CryptoService {

    /**
     * 解密请求：RSA 解 AES key，再用客户端上传的 IV 做 CBC 解密。
     * DTO 使用 {@link DecryptRequestV3}（基类字段 + iv）。
     */
    public DecryptResult decryptRequest(DecryptRequestV3 request, PrivateKey rsaPrivateKey) throws Exception {
        log.info("[v3] RSA 解 AES key + AES-CBC 解业务数据");

        byte[] aesKey = rsaDecryptPkcs1(request.getEncryptedKey(), rsaPrivateKey);

        // 相对 v1/v2：多传 iv；CBC 没有正确 IV 解不出第一个明文块
        byte[] plaintextBytes = aesDecryptCbc(request.getEncryptedData(), aesKey, request.getIv());
        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        return new DecryptResult(aesKey, plaintext);
    }

    /**
     * 加密响应：新随机 IV + 签 concat(iv, ciphertext)。
     * 返回 {@link EncryptResponseV3}，比基类多一个 iv 字段。
     */
    public EncryptResponseV3 encryptResponse(String responsePlaintext, byte[] aesKey, PrivateKey signingKey) throws Exception {
        log.info("[v3] AES-CBC 加密响应 + 签名 (iv || ciphertext)");

        // 必须 SecureRandom：java.util.Random 可预测，不适合密码学
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        // CBC 初始化时必须带 IvParameterSpec，否则会抛异常
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));
        byte[] encrypted = aesCipher.doFinal(responsePlaintext.getBytes(StandardCharsets.UTF_8));

        // 相对 v2：签名范围从「只签密文」扩大到「IV + 密文」
        // 前端验签必须按同样顺序拼接字节
        byte[] toSign = concat(iv, encrypted);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(signingKey);
        signature.update(toSign);
        byte[] sig = signature.sign();

        return new EncryptResponseV3(
                Base64.getEncoder().encodeToString(iv),
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

    /**
     * CBC：P₁ = AES_decrypt(C₁) ⊕ IV。缺 IV / 长度不对必须拒绝，不能默默用全 0。
     */
    private static byte[] aesDecryptCbc(String encryptedDataB64, byte[] aesKey, String ivB64) throws Exception {
        // 可能是旧版前端忘了升级，字段缺失时给出明确错误
        if (!StringUtils.hasLength(ivB64)) {
            throw new IllegalArgumentException("v3 缺少 iv：AES-CBC 必需");
        }
        byte[] iv = Base64.getDecoder().decode(ivB64);
        // AES 块大小 16 字节；其它长度说明协议或编码出错
        if (iv.length != 16) {
            throw new IllegalArgumentException("v3 iv 长度错误：期望 16 字节，实际 " + iv.length);
        }

        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));
        return aes.doFinal(Base64.getDecoder().decode(encryptedDataB64));
    }

    /** 简单字节拼接：签名输入 = iv || ciphertext */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
