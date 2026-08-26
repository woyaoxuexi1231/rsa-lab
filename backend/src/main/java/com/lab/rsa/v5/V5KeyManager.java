package com.lab.rsa.v5;

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
 * v5 多版本密钥表（逻辑同 v4，独立一份避免与 v4 Demo 互相抢密钥）。
 *
 * <p>token 校验时比对的是本表里的 fingerprint；所以 v4 下发的 token 不能拿来调 v5。
 */
@Service
@Slf4j
public class V5KeyManager {
    private final Map<String, KeyVersion> keys = new LinkedHashMap<>();
    private String latestKeyVersion;

    @PostConstruct
    public void init() throws Exception {
        generateKey("1", KeyVersion.Status.DEPRECATED);
        generateKey("2", KeyVersion.Status.ACTIVE);
        this.latestKeyVersion = "2";
        log.info("[v5 密钥] 多版本初始化完成，latest={}", latestKeyVersion);
    }

    public KeyVersion getLatestKey() {
        return keys.get(latestKeyVersion);
    }

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

        // 与 v4 相同：fingerprint 进 token，防止「只改版本号、换一把公钥」
        String fingerprint = calculateFingerprint(pair.getPublic());
        keys.put(version, KeyVersion.builder()
                .version(version)
                .publicKey(pair.getPublic())
                .privateKey(pair.getPrivate())
                .fingerprint(fingerprint)
                .status(status)
                .build());
        log.info("[v5 密钥] version={} status={} fingerprint={}", version, status, fingerprint);
    }

    private String calculateFingerprint(PublicKey publicKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(digest.digest(publicKey.getEncoded()));
    }
}
