package com.lab.rsa.v2;

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
 * v2 HTTP 入口：请求 DTO 与 v1 相同（继承树基类）；响应里 {@code signature} 不再为 null。
 * 前端必须先验签再解密，否则等于没加这层保护。
 */
@RestController
@RequestMapping("/api/rsa/v2")
@RequiredArgsConstructor
@Slf4j
public class V2Controller {
    private final V2KeyManager keyManager;
    private final V2CryptoService cryptoService;

    @GetMapping("/key")
    public ResponseEntity<KeyResponse> key() {
        log.info("[API][v2] 获取公钥");
        // 同一把公钥：既用于加密 AES key，也用于验签响应
        return ResponseEntity.ok(new KeyResponse(
                keyManager.getPublicKeyPem(),
                "v2：RSA-PKCS1 + AES-ECB + 响应 SHA256withRSA 签名"
        ));
    }

    @PostMapping("/secure/echo")
    public ResponseEntity<?> secureEcho(@RequestBody DecryptRequest request) {
        log.info("[API][v2] /secure/echo");
        try {
            V2CryptoService.DecryptResult decrypted =
                    cryptoService.decryptRequest(request, keyManager.getPrivateKey());

            String responsePlaintext = "服务端收到你的明文: " + decrypted.plaintext();

            // 相对 v1：多传私钥，用于给响应密文签名
            EncryptResponse response = cryptoService.encryptResponse(
                    responsePlaintext, decrypted.aesKey(), keyManager.getPrivateKey());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("[API][v2] 处理失败", e);
            return ResponseEntity.badRequest().body("Request failed: " + e.getMessage());
        }
    }
}
