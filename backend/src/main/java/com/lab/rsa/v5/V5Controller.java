package com.lab.rsa.v5;

import com.lab.rsa.common.model.KeyVersion;
import com.lab.rsa.common.service.NonceService;
import com.lab.rsa.common.service.TokenService;
import com.lab.rsa.dto.DecryptRequestV5;
import com.lab.rsa.dto.EncryptResponse;
import com.lab.rsa.dto.KeyResponseV5;
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
 * v5：在 v4 之上防重放。
 *
 * <p>请求 DTO = {@link DecryptRequestV5}（VersionedDecryptRequest + timestamp/nonce/HMAC）；
 * 公钥响应 = {@link KeyResponseV5}（V4 + replayWindowMs）。
 *
 * <h3>校验顺序（与代码一致）</h3>
 * keyVersion → token → 解 AES key → HMAC → 时间窗 → 消费 nonce → 解密业务。
 */
@RestController
@RequestMapping("/api/rsa/v5")
@RequiredArgsConstructor
@Slf4j
public class V5Controller {
    private final V5KeyManager keyManager;
    private final V5CryptoService cryptoService;
    private final TokenService tokenService;
    private final NonceService nonceService;

    @GetMapping("/key")
    public ResponseEntity<KeyResponseV5> key() throws Exception {
        KeyVersion kv = keyManager.getLatestKey();
        long expireAtMs = System.currentTimeMillis() + 10 * 60 * 1000L;
        String token = tokenService.issueToken(kv.getVersion(), kv.getFingerprint(), expireAtMs);

        log.info("[API][v5] 获取公钥 keyVersion={} status={}", kv.getVersion(), kv.getStatus());
        return ResponseEntity.ok(new KeyResponseV5(
                kv.getVersion(),
                keyManager.getPublicKeyPem(kv.getPublicKey()),
                "v5：keyVersion + token + timestamp + nonce + HMAC 防重放",
                token,
                // 多出来的字段：让前端知道允许的时钟偏差
                nonceService.getReplayWindowMs()
        ));
    }

    @PostMapping("/secure/echo")
    public ResponseEntity<?> secureEcho(@RequestBody DecryptRequestV5 request) {
        try {
            // ---- ① keyVersion（继承自 VersionedDecryptRequest）----
            if (!StringUtils.hasLength(request.getKeyVersion())) {
                return ResponseEntity.badRequest().body("Request failed: missing keyVersion");
            }
            KeyVersion kv = keyManager.getKey(request.getKeyVersion());
            if (kv == null) {
                return ResponseEntity.badRequest().body("Request failed: invalid keyVersion");
            }

            // ---- ② token：防伪造版本 / 防过期凭证 ----
            long nowMs = System.currentTimeMillis();
            if (!tokenService.verifyToken(request.getToken(), kv.getVersion(), kv.getFingerprint(), nowMs)) {
                return ResponseEntity.badRequest().body("Request failed: invalid token");
            }

            // ---- ③ 解出 AES key：HMAC 的密钥材料 ----
            byte[] aesKey = cryptoService.decryptAesKey(request, kv.getPrivateKey());

            // ---- ④ HMAC：证明 timestamp/nonce/密文/keyVersion 没被改 ----
            // 必须先于时间窗/nonce：否则攻击者改时间戳可能绕过窗口判断的语义讨论更乱
            if (!cryptoService.verifyRequestSignature(request, aesKey)) {
                return ResponseEntity.badRequest().body("Request failed: invalid request signature");
            }

            // ---- ⑤ 时间窗：拒绝囤积过久的旧包 ----
            if (!nonceService.isTimestampWithinWindow(request.getTimestamp(), nowMs)) {
                return ResponseEntity.badRequest().body("Request failed: timestamp out of allowed window");
            }

            // ---- ⑥ nonce 一次性：同一包再发 → false（前端「重放」演示看这里）----
            if (!nonceService.consumeNonce(request.getNonce(), nowMs)) {
                return ResponseEntity.badRequest().body("Request failed: nonce already used");
            }

            // ---- ⑦ 全部通过，才碰业务明文 ----
            log.info("[API][v5] /secure/echo keyVersion={} timestamp={} nonce={}",
                    kv.getVersion(), request.getTimestamp(), request.getNonce());
            V5CryptoService.DecryptResult decrypted = cryptoService.decryptPayload(request, aesKey);
            String responsePlaintext = "服务端收到你的明文: " + decrypted.plaintext();
            EncryptResponse response = cryptoService.encryptResponse(responsePlaintext, decrypted.aesKey());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("[API][v5] 处理失败", e);
            return ResponseEntity.badRequest().body("Request failed: " + e.getMessage());
        }
    }
}
