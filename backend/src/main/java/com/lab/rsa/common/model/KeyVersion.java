package com.lab.rsa.common.model;

import lombok.Builder;
import lombok.Data;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * 一把「带版本号」的 RSA 密钥（供 v4/v5 使用）。
 *
 * <p>生产里密钥会轮换：新密钥 ACTIVE，旧密钥先 DEPRECATED（仍可解密历史密文），
 * 再变为 REVOKED。客户端上报的 {@code keyVersion} 本身不可信，所以还要配合
 * {@link com.lab.rsa.common.service.TokenService} 把版本绑到服务端签发的 token 上。
 *
 * <p>本实验室目前<strong>演示了多版本存储与 token 绑定</strong>，但尚未在业务里强制
 * 拒绝 DEPRECATED/REVOKED（留给你继续完善的练习点）。
 */
@Data
@Builder
public class KeyVersion {
    /** 客户端/服务端约定的版本号字符串，如 "1"、"2" */
    private String version;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    /**
     * 公钥指纹（通常是公钥 DER 的 SHA-256）。
     * token 里会带上 fingerprint，防止攻击者把旧版本号配到另一把公钥上。
     */
    private String fingerprint;
    private Status status;

    public enum Status {
        /** 当前对外下发、用于新加密的密钥 */
        ACTIVE,
        /** 已轮换下线，但仍可能用于解密旧密文 */
        DEPRECATED,
        /** 已作废，不应再使用 */
        REVOKED
    }
}
