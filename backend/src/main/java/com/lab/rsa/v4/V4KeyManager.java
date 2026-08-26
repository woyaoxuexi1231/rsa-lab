package com.lab.rsa.v4;

import com.lab.rsa.common.PemUtils;
import com.lab.rsa.common.model.KeyVersion;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * v4/v5 起的多版本密钥表。
 *
 * <h3>为什么要多版本？</h3>
 * 生产密钥必须能轮换：新密钥对外加密，旧密钥暂时保留以解密历史数据。
 * 本 Demo 启动时预置：
 * <ul>
 *   <li>version=1 → DEPRECATED（旧钥匙，仍可查到）</li>
 *   <li>version=2 → ACTIVE（{@code GET /key} 默认下发这一把）</li>
 * </ul>
 *
 * <h3>练习点</h3>
 * 当前 {@link #getKey} 只要版本存在就返回，未按 {@link KeyVersion.Status} 拒绝 DEPRECATED。
 * 你可以试着加上：ACTIVE 才允许加密路径、DEPRECATED 仅允许解密旧数据等策略。
 */
@Service
@Slf4j
public class V4KeyManager {
    private final Map<String, KeyVersion> keys = new LinkedHashMap<>();
    private String latestKeyVersion;

    @PostConstruct
    public void init() throws Exception {
        generateKey("1", KeyVersion.Status.DEPRECATED);
        generateKey("2", KeyVersion.Status.ACTIVE);
        this.latestKeyVersion = "2";
        log.info("[v4 密钥] 多版本初始化完成，latest={}", latestKeyVersion);
    }

    /** 对外下发用的「当前最新」密钥 */
    public KeyVersion getLatestKey() {
        return keys.get(latestKeyVersion);
    }

    /** 按客户端上报的版本号查找；不存在则返回 null */
    public KeyVersion getKey(String keyVersion) {
        return keys.get(keyVersion);
    }

    public String getPublicKeyPem(PublicKey publicKey) {
        return PemUtils.toPublicKeyPem(publicKey);
    }

    private void generateKey(String version, KeyVersion.Status status) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair pair = gen.generateKeyPair();

        // fingerprint 写入 KeyVersion，供 TokenService 绑定；版本号相同但公钥不同时也能区分
        String fingerprint = calculateFingerprint(pair.getPublic());
        keys.put(version, KeyVersion.builder()
                .version(version)
                .publicKey(pair.getPublic())
                .privateKey(pair.getPrivate())
                .fingerprint(fingerprint)
                .status(status)
                .build());
        log.info("[v4 密钥] version={} status={} fingerprint={}", version, status, fingerprint);
    }

    /** 公钥指纹：把公钥 DER 做 SHA-256，再 Base64。token 会绑定这个值，防「版本号对、公钥不对」。 */
    private String calculateFingerprint(PublicKey publicKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(digest.digest(publicKey.getEncoded()));
    }
}
