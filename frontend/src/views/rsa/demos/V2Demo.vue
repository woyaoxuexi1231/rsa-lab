<script setup>
import { computed } from 'vue'
import RsaDemoShell from '../RsaDemoShell.vue'
import { useRsaDemo } from '../../../composables/useRsaDemo'
import { buildV2Payload, decryptV2Response } from '../../../utils/rsaCrypto'

const demo = useRsaDemo({
  version: 'v2',
  build: (info, text) => buildV2Payload(info.publicKey, text),
  decrypt: (response, aesKey, info) => decryptV2Response(response, aesKey, info.publicKey)
})

const keyHint = computed(() => (demo.keyInfo ? `公钥已加载 — ${demo.keyInfo.algorithm}` : ''))
</script>

<template>
  <RsaDemoShell
    title="2️⃣ v2 · 响应签名"
    subtitle="在 v1 上为响应密文增加 SHA256withRSA 签名"
    problem="攻击者可篡改响应密文；客户端解密后只能得到乱码或错误内容，却不知道被改过。"
    solution="服务端用 RSA 私钥对密文字节签名；前端用公钥先验签，再 AES 解密。"
    v-model:plaintext="demo.plaintext"
    :key-status="demo.keyStatus"
    :key-hint="keyHint"
    :loading="demo.loading"
    :log-text="demo.logText"
    :has-logs="demo.logs.length > 0"
    @send="demo.sendNewRequest"
    @reload="demo.loadKey"
  />
</template>
