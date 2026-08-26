package com.lab.rsa.v1;

import com.lab.rsa.dto.DecryptRequest;
import com.lab.rsa.dto.EncryptResponse;
import com.lab.rsa.dto.KeyResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * v1 HTTP 入口：最小混合加密闭环。
 *
 * <pre>
 *  前端                         后端
 *   |-- GET /key -------------->|  下发 RSA 公钥
 *   |  随机 AES key              |
 *   |  AES 加密明文              |
 *   |  RSA 公钥加密 AES key      |
 *   |-- POST /secure/echo ----->|  私钥解 AES key → AES 解明文
 *   |                           |  再用同一 AES key 加密 echo
 *   |&lt;-- encryptedData ---------|
 * </pre>
 *
 * <p>路径必须带完整前缀 {@code /api/rsa/v1}（Gateway 不剥前缀）。
 */
@RestController
@RequestMapping("/api/rsa/v1")
@RequiredArgsConstructor
@Slf4j
public class V1Controller {
    private final V1KeyManager keyManager;
    private final V1CryptoService cryptoService;

    /** 只下发公钥；私钥永不出现在响应里 */
    @GetMapping("/key")
    public ResponseEntity<KeyResponse> key() {
        log.info("[API][v1] 获取公钥");
        return ResponseEntity.ok(new KeyResponse(
                keyManager.getPublicKeyPem(),
                "v1：RSA-PKCS1 + AES-ECB（无签名）"
        ));
    }

    /**
     * 解密请求明文再加密回显。
     * echo 只是占位业务；真实项目里这里会是下单、改密等。
     */
    @PostMapping("/secure/echo")
    public ResponseEntity<?> secureEcho(@RequestBody DecryptRequest request) {
        log.info("[API][v1] /secure/echo");
        try {
            // 混合解密：得到明文，同时拿回 AES key 供回包使用
            V1CryptoService.DecryptResult decrypted =
                    cryptoService.decryptRequest(request, keyManager.getPrivateKey());

            // 「业务处理」在教学里简化成字符串拼接
            String responsePlaintext = "服务端收到你的明文: " + decrypted.plaintext();

            // 复用请求侧 AES key 加密响应 → 客户端无需再协商
            EncryptResponse response = cryptoService.encryptResponse(responsePlaintext, decrypted.aesKey());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("[API][v1] 处理失败", e);
            // 教学接口直接回错误串；生产应统一错误码且少泄露密码学细节
            return ResponseEntity.badRequest().body("Request failed: " + e.getMessage());
        }
    }
}
