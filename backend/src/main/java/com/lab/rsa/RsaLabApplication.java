package com.lab.rsa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * RSA 混合加密实验室入口。
 *
 * <p>本服务把 v1→v5 五套「循序渐进」的加解密 Demo 放在同一个 Spring Boot 进程里，
 * 方便对照学习。API 前缀统一为 {@code /api/rsa/**}，各版本再拆到
 * {@code /api/rsa/v1} … {@code /api/rsa/v5}。
 *
 * <p>学习路线（每一步都在解决上一步还没解决的安全问题）：
 * <ol>
 *   <li>v1：跑通 RSA + AES 混合加密最小闭环（无签名）</li>
 *   <li>v2：给响应加 RSA 签名，防止密文被篡改</li>
 *   <li>v3：AES-ECB → AES-CBC，并保护 IV</li>
 *   <li>v4：多版本密钥 + token，防止客户端伪造 keyVersion 降级</li>
 *   <li>v5：timestamp + nonce + HMAC，防止整包重放</li>
 * </ol>
 */
@SpringBootApplication
public class RsaLabApplication {
    public static void main(String[] args) {
        SpringApplication.run(RsaLabApplication.class, args);
    }
}
