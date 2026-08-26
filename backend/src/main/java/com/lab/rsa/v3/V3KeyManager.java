package com.lab.rsa.v3;

import com.lab.rsa.common.PemUtils;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * v3 密钥管理：独立 RSA 密钥对。
 * 用法与 v2 相同（解密 AES key + 签响应），变化在对称加密模式与签名范围。
 */
@Service
@Slf4j
public class V3KeyManager {
    private KeyPair keyPair;

    @PostConstruct
    public void init() throws Exception {
        // 独立密钥对：算法升级（CBC）与密钥存储无关，但 Demo 仍按版本隔离
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        this.keyPair = gen.generateKeyPair();
        log.info("[v3 密钥] RSA-2048 单密钥对已生成");
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    public String getPublicKeyPem() {
        return PemUtils.toPublicKeyPem(getPublicKey());
    }
}
