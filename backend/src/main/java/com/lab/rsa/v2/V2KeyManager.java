package com.lab.rsa.v2;

import com.lab.rsa.common.PemUtils;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * v2 密钥管理：独立的一把 RSA 密钥对（不与 v1 共享）。
 *
 * <p>各版本自备密钥，是为了让你在前端切换 Demo 时互不干扰；
 * 同一进程里 v1 的公钥解不开 v2 的请求。
 *
 * <p>额外：v2 用<strong>同一把</strong> RSA 私钥既解密 AES key，又给响应签名
 * （私钥的「解密」与「签名」是两种运算，但可以共用同一密钥对——教学上常见简化）。
 */
@Service
@Slf4j
public class V2KeyManager {
    private KeyPair keyPair;

    @PostConstruct
    public void init() throws Exception {
        // 与 v1 隔离：故意各自生成，前端切到 v2 时不能复用 v1 公钥
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        this.keyPair = gen.generateKeyPair();
        log.info("[v2 密钥] RSA-2048 单密钥对已生成（兼作解密与响应签名）");
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
