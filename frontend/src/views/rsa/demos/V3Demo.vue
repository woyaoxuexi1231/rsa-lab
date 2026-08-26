<script setup>
import { computed } from 'vue'
import RsaDemoShell from '../RsaDemoShell.vue'
import { useRsaDemo } from '../../../composables/useRsaDemo'
import { buildV3Payload, decryptV3Response } from '../../../utils/rsaCrypto'

const demo = useRsaDemo({
  version: 'v3',
  build: (info, text) => buildV3Payload(info.publicKey, text),
  decrypt: (response, aesKey, info) => decryptV3Response(response, aesKey, info.publicKey)
})

const keyHint = computed(() => (demo.keyInfo ? `公钥已加载 — ${demo.keyInfo.algorithm}` : ''))
</script>

<template>
  <RsaDemoShell
    title="3️⃣ v3 · AES-CBC + IV"
    subtitle="用 CBC 替代 ECB，并对 (iv || 密文) 签名"
    problem="AES-ECB 相同明文块产生相同密文块，会泄露模式；且 IV 若被篡改会影响解密结果。"
    solution="每次随机 IV + AES-CBC；响应签名覆盖 iv 与密文的拼接，前端先验签再解密。"
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
