<script setup>
import { computed } from 'vue'
import RsaDemoShell from '../RsaDemoShell.vue'
import { useRsaDemo } from '../../../composables/useRsaDemo'
import { buildV5Payload, decryptV5Response } from '../../../utils/rsaCrypto'

const demo = useRsaDemo({
  version: 'v5',
  replay: true,
  build: (info, text) => buildV5Payload(info.publicKey, text, info),
  decrypt: (response, aesKey) => decryptV5Response(response, aesKey)
})

const keyHint = computed(() => {
  if (!demo.keyInfo) return ''
  return `公钥已加载 — keyVersion=${demo.keyInfo.keyVersion}，窗口 ${demo.keyInfo.replayWindowMs}ms`
})
</script>

<template>
  <RsaDemoShell
    title="5️⃣ v5 · 防重放"
    subtitle="timestamp + nonce + HMAC-SHA256 请求签名"
    problem="合法请求包可被原样重放：token 未过期时，服务端会再次执行同一业务。"
    solution="每次请求带唯一 nonce 与时间戳，并用 AES key 对 keyVersion|timestamp|nonce|密文 做 HMAC。先发成功，再点「重放上一包」应被拒绝。"
    v-model:plaintext="demo.plaintext"
    :key-status="demo.keyStatus"
    :key-hint="keyHint"
    :loading="demo.loading"
    :log-text="demo.logText"
    :has-logs="demo.logs.length > 0"
    :replay="true"
    @send="demo.sendNewRequest"
    @replay="demo.replayLast"
    @reload="demo.loadKey"
  />
</template>
