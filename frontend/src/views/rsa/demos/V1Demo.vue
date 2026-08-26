<script setup>
import { computed } from 'vue'
import RsaDemoShell from '../RsaDemoShell.vue'
import { useRsaDemo } from '../../../composables/useRsaDemo'
import { buildV1Payload, decryptV1Response } from '../../../utils/rsaCrypto'

const demo = useRsaDemo({
  version: 'v1',
  build: (info, text) => buildV1Payload(info.publicKey, text),
  decrypt: (response, aesKey) => decryptV1Response(response, aesKey)
})

const keyHint = computed(() => (demo.keyInfo ? `公钥已加载 — ${demo.keyInfo.algorithm}` : ''))
</script>

<template>
  <RsaDemoShell
    title="1️⃣ v1 · 最小闭环"
    subtitle="RSA-PKCS1 包 AES key + AES-ECB 加密业务数据"
    problem="RSA 不适合直接加密大段业务数据；只用 AES 又没法安全下发密钥。"
    solution="混合加密：客户端随机 AES key 加密明文，再用服务端 RSA 公钥包住 AES key。"
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
