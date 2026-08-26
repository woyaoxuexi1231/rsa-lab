package com.lab.rsa.v1;

import com.lab.rsa.common.PemUtils;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * v1 密钥管理：进程启动时生成一把 RSA-2048 密钥对。
 *
 * <p>公钥通过 {@code GET /api/rsa/v1/key} 下发给前端；私钥永不离开服务端。
 * 重启进程会重新生成，旧密文全部失效——教学 Demo 可接受，生产应持久化并做轮换（见 v4）。
 */
@Service
@Slf4j
public class V1KeyManager {
    private KeyPair keyPair;

    @PostConstruct
    public void init() throws Exception {
        // 2048 bit 是当前教学/一般业务的常用下限；更短（如 1024）已不安全
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        this.keyPair = gen.generateKeyPair();
        log.info("[v1 密钥] RSA-2048 单密钥对已生成");
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    /** 转成 PEM，供前端 node-forge 解析 */
    public String getPublicKeyPem() {
        return PemUtils.toPublicKeyPem(getPublicKey());
    }
}
