<script setup>
import { computed } from 'vue'
import RsaDemoShell from '../RsaDemoShell.vue'
import { useRsaDemo } from '../../../composables/useRsaDemo'
import { buildV4Payload, decryptV4Response } from '../../../utils/rsaCrypto'

const demo = useRsaDemo({
  version: 'v4',
  build: (info, text) => buildV4Payload(info.publicKey, text, info),
  decrypt: (response, aesKey) => decryptV4Response(response, aesKey)
})

const keyHint = computed(() =>
  demo.keyInfo ? `公钥已加载 — keyVersion=${demo.keyInfo.keyVersion}` : ''
)
</script>

<template>
  <RsaDemoShell
    title="4️⃣ v4 · 密钥版本 + token"
    subtitle="多版本密钥与版本绑定 token（教学骨架）"
    problem="客户端上报的 keyVersion 不可信；攻击者可能伪造旧版本实现降级攻击。"
    solution="服务端下发与 fingerprint 绑定的短时 token；请求必须携带匹配的 keyVersion + token。加解密仍为 ECB，OAEP/GCM 留作后续。"
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
