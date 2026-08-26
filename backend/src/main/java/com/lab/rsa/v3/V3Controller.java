package com.lab.rsa.v3;

import com.lab.rsa.dto.DecryptRequestV3;
import com.lab.rsa.dto.EncryptResponseV3;
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
 * v3 HTTP 入口：请求体类型升级为 {@link DecryptRequestV3}（多了 iv）；
 * 响应类型升级为 {@link EncryptResponseV3}（多了 iv）。
 * 公钥响应仍用基类 {@link KeyResponse}（本版没加版本/token）。
 */
@RestController
@RequestMapping("/api/rsa/v3")
@RequiredArgsConstructor
@Slf4j
public class V3Controller {
    private final V3KeyManager keyManager;
    private final V3CryptoService cryptoService;

    @GetMapping("/key")
    public ResponseEntity<KeyResponse> key() {
        log.info("[API][v3] 获取公钥");
        return ResponseEntity.ok(new KeyResponse(
                keyManager.getPublicKeyPem(),
                "v3：RSA-PKCS1 + AES-CBC(iv) + 响应签名(iv||密文)"
        ));
    }

    /**
     * 请求 iv：客户端加密时生成；响应 iv：服务端回包时重新生成——二者无关。
     */
    @PostMapping("/secure/echo")
    public ResponseEntity<?> secureEcho(@RequestBody DecryptRequestV3 request) {
        log.info("[API][v3] /secure/echo");
        try {
            // Jackson 反序列化到 V3 子类，getIv() 才有值
            V3CryptoService.DecryptResult decrypted =
                    cryptoService.decryptRequest(request, keyManager.getPrivateKey());

            String responsePlaintext = "服务端收到你的明文: " + decrypted.plaintext();

            // 返回 EncryptResponseV3：JSON 比 v1/v2 多一个 iv 字段
            EncryptResponseV3 response = cryptoService.encryptResponse(
                    responsePlaintext, decrypted.aesKey(), keyManager.getPrivateKey());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("[API][v3] 处理失败", e);
            return ResponseEntity.badRequest().body("Request failed: " + e.getMessage());
        }
    }
}
