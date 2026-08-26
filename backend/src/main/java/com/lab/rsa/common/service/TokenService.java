package com.lab.rsa.common.service;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 * 为「公钥下发」签发短时 token（v4/v5）。
 *
 * <h3>要解决什么问题？</h3>
 * 客户端可以任意填写 {@code keyVersion}。若没有额外约束，攻击者可能：
 * <ul>
 *   <li>故意上报已废弃的弱算法版本（协议降级）</li>
 *   <li>把版本号改成仍存在但意图不同的密钥</li>
 * </ul>
 * 所以服务端在 {@code GET /key} 时，除了给公钥，还签发一段
 * 「版本号 + 公钥指纹 + 过期时间」绑定的 token；后续 {@code /secure/echo}
 * 必须带上这份 token，且校验通过后才解密。
 *
 * <h3>为什么用 ECDSA 而不是 HMAC？</h3>
 * 这里的签发密钥只在服务端持有（ECDSA 私钥）。教学上强调：
 * token 的完整性由服务端签名保证，客户端无法伪造。
 * （生产里更常见 JWT/JWS；本 Demo 用手写 {@code payload.sig} 便于看清字段。）
 *
 * <p>注意：token 防的是「版本/指纹被篡改」，<strong>防不了整包重放</strong>——那是 v5 的课题。
 */
@Service
@Slf4j
public class TokenService {
    private PrivateKey signingKey;
    private PublicKey verifyKey;

    @PostConstruct
    public void init() throws Exception {
        // EC P-256：签名短、速度快，适合「短时凭证」场景的教学演示
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(256);
        KeyPair kp = gen.generateKeyPair();
        this.signingKey = kp.getPrivate();
        this.verifyKey = kp.getPublic();
        log.info("[Token服务] ECDSA 签发密钥已就绪（进程内随机生成，重启后旧 token 全部失效）");
    }

    /**
     * 签发 token。
     *
     * <p>格式：{@code Base64(payload) + "." + Base64(signature)}，其中
     * {@code payload = keyVersion + ":" + fingerprint + ":" + expireAtMs}。
     *
     * @param keyVersion  当前下发的密钥版本
     * @param fingerprint 该版本公钥指纹
     * @param expireAtMs  过期绝对时间（epoch millis）
     */
    public String issueToken(String keyVersion, String fingerprint, long expireAtMs) throws Exception {
        // 明文载荷：三个字段用冒号拼接，验签通过后再拆开比对
        String payload = keyVersion + ":" + fingerprint + ":" + expireAtMs;

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(signingKey);
        signer.update(payload.getBytes(StandardCharsets.UTF_8));
        byte[] sig = signer.sign();

        // 外形故意做成 JWT 风格的两段：payload.sig，方便肉眼调试（不是标准 JWT）
        return Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                + "."
                + Base64.getEncoder().encodeToString(sig);
    }

    /**
     * 校验 token 是否仍绑定到「期望的版本 + 指纹」，且未过期。
     *
     * @return true 表示可用；任何解析/验签/字段不匹配都返回 false（故意不抛细节，避免信息泄露）
     */
    public boolean verifyToken(String token, String expectedKeyVersion, String expectedFingerprint, long nowMs) {
        try {
            if (!StringUtils.hasLength(token)) {
                return false;
            }
            String[] parts = token.split("\\.");
            if (parts.length != 2) {
                return false;
            }

            String payload = new String(Base64.getDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            byte[] sig = Base64.getDecoder().decode(parts[1]);

            // 1) 先验签：签名不对说明被篡改或不是本服务签发
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(verifyKey);
            verifier.update(payload.getBytes(StandardCharsets.UTF_8));
            if (!verifier.verify(sig)) {
                return false;
            }

            String[] fields = payload.split(":");
            if (fields.length != 3) {
                return false;
            }
            String keyVersion = fields[0];
            String fingerprint = fields[1];
            long expireAt = Long.parseLong(fields[2]);

            // 2) 再核对业务绑定：必须对应当前这把密钥，而不是「任意合法签名」
            if (!keyVersion.equals(expectedKeyVersion)) {
                return false;
            }
            if (!fingerprint.equals(expectedFingerprint)) {
                return false;
            }
            // 3) 过期检查：过期 token 即使签名正确也拒绝
            return nowMs <= expireAt;
        } catch (Exception e) {
            // 解析失败统一当无效，避免把异常细节回给客户端
            return false;
        }
    }
}
