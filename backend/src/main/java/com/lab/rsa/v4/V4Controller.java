package com.lab.rsa.v4;

import com.lab.rsa.common.model.KeyVersion;
import com.lab.rsa.common.service.TokenService;
import com.lab.rsa.dto.DecryptRequestV4;
import com.lab.rsa.dto.EncryptResponse;
import com.lab.rsa.dto.KeyResponseV4;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * v4：解决「客户端上报的 keyVersion 不可信」。
 *
 * <p>响应类型升级为 {@link KeyResponseV4}（多了 keyVersion + token）；
 * 请求类型升级为 {@link DecryptRequestV4}（继承 VersionedDecryptRequest）。
 * 仍防不了整包重放 → v5。
 */
@RestController
@RequestMapping("/api/rsa/v4")
@RequiredArgsConstructor
@Slf4j
public class V4Controller {
    private final V4KeyManager keyManager;
    private final V4CryptoService cryptoService;
    private final TokenService tokenService;

    @GetMapping("/key")
    public ResponseEntity<KeyResponseV4> key() throws Exception {
        // 只下发 ACTIVE 最新版；旧版 DEPRECATED 仍留在 KeyManager 里供查表
        KeyVersion kv = keyManager.getLatestKey();

        // token 10 分钟有效：过期后即使签名算法正确也会被拒
        long expireAtMs = System.currentTimeMillis() + 10 * 60 * 1000L;
        String token = tokenService.issueToken(kv.getVersion(), kv.getFingerprint(), expireAtMs);

        log.info("[API][v4] 获取公钥 keyVersion={} status={}", kv.getVersion(), kv.getStatus());
        return ResponseEntity.ok(new KeyResponseV4(
                kv.getVersion(),
                keyManager.getPublicKeyPem(kv.getPublicKey()),
                "v4：keyVersion + token（加解密仍为 ECB；OAEP/GCM 待继续完善）",
                token
        ));
    }

    @PostMapping("/secure/echo")
    public ResponseEntity<?> secureEcho(@RequestBody DecryptRequestV4 request) {
        try {
            // ---- 1) keyVersion：客户端可控，先做存在性与查表 ----
            if (!StringUtils.hasLength(request.getKeyVersion())) {
                return ResponseEntity.badRequest().body("Request failed: missing keyVersion");
            }
            KeyVersion kv = keyManager.getKey(request.getKeyVersion());
            if (kv == null) {
                // 随便填一个不存在的版本号，到这里拦住
                return ResponseEntity.badRequest().body("Request failed: invalid keyVersion");
            }

            // ---- 2) token：必须绑定「这把密钥的 version + fingerprint」且未过期 ----
            long nowMs = System.currentTimeMillis();
            if (!tokenService.verifyToken(request.getToken(), kv.getVersion(), kv.getFingerprint(), nowMs)) {
                return ResponseEntity.badRequest().body("Request failed: invalid token");
            }

            // ---- 3) 版本校验通过后，才用对应私钥做混合解密 ----
            log.info("[API][v4] /secure/echo keyVersion={} status={}", kv.getVersion(), kv.getStatus());
            V4CryptoService.DecryptResult decrypted =
                    cryptoService.decryptRequest(request, kv.getPrivateKey());

            String responsePlaintext = "服务端收到你的明文: " + decrypted.plaintext();
            EncryptResponse response = cryptoService.encryptResponse(responsePlaintext, decrypted.aesKey());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("[API][v4] 处理失败", e);
            return ResponseEntity.badRequest().body("Request failed: " + e.getMessage());
        }
    }
}
