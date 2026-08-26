import { computed, onMounted, reactive, ref } from 'vue'
import { fetchPublicKey, secureEcho } from '../api/rsa'

/**
 * @param {object} opts
 * @param {string} opts.version  'v1' | 'v2' | ...
 * @param {(keyInfo, plaintext) => { payload, aesKeyBytes }} opts.build
 * @param {(response, aesKeyBytes, keyInfo) => string} opts.decrypt
 * @param {boolean} [opts.replay]
 */
export function useRsaDemo ({ version, build, decrypt, replay = false }) {
  const plaintext = ref('Hello, RSA lab!')
  const keyInfo = ref(null)
  const keyStatus = ref('loading')
  const loading = ref(false)
  const logs = ref([])
  const lastPayload = ref(null)
  const lastAesKey = ref(null)

  const logText = computed(() =>
    logs.value.map(line => `[${line.time}] [${line.type}] ${line.message}`).join('\n')
  )

  function pushLog (message, type = 'info') {
    logs.value.push({ time: new Date().toLocaleTimeString(), message, type })
    if (logs.value.length > 80) logs.value.splice(0, logs.value.length - 80)
  }

  async function loadKey () {
    keyStatus.value = 'loading'
    pushLog(`请求 GET /api/rsa/${version}/key ...`)
    try {
      const data = await fetchPublicKey(version)
      keyInfo.value = data
      keyStatus.value = 'ready'
      const extra = data.keyVersion != null ? `，keyVersion=${data.keyVersion}` : ''
      const windowHint = data.replayWindowMs != null ? `，窗口=${data.replayWindowMs}ms` : ''
      pushLog(`获取成功：${data.algorithm}${extra}${windowHint}`, 'success')
    } catch (e) {
      keyStatus.value = 'error'
      pushLog('获取失败：' + e.message, 'error')
    }
  }

  async function sendNewRequest () {
    if (!keyInfo.value) {
      pushLog('公钥尚未加载', 'warn')
      return
    }
    loading.value = true
    try {
      const { payload, aesKeyBytes } = build(keyInfo.value, plaintext.value)
      lastPayload.value = payload
      lastAesKey.value = aesKeyBytes
      await sendPayload(payload, aesKeyBytes, '新请求')
    } catch (e) {
      pushLog('出错: ' + e.message, 'error')
    } finally {
      loading.value = false
    }
  }

  async function replayLast () {
    if (!replay) return
    if (!lastPayload.value || !lastAesKey.value) {
      pushLog('还没有可重放的请求包，先发送一次新请求', 'warn')
      return
    }
    loading.value = true
    try {
      await sendPayload(lastPayload.value, lastAesKey.value, '重放上一包')
    } finally {
      loading.value = false
    }
  }

  async function sendPayload (payload, aesKeyBytes, actionName) {
    pushLog(`${actionName}：POST /api/rsa/${version}/secure/echo ...`)
    const resp = await secureEcho(version, payload)
    if (!resp.ok) {
      const msg = typeof resp.data === 'string' ? resp.data : (resp.text || `HTTP ${resp.status}`)
      pushLog('服务端拒绝: ' + msg, 'error')
      return
    }
    try {
      const text = decrypt(resp.data, aesKeyBytes, keyInfo.value)
      pushLog('响应解密成功: ' + text, 'success')
    } catch (e) {
      pushLog('响应处理失败: ' + e.message, 'error')
    }
  }

  onMounted(loadKey)

  // refs 放进 reactive 后访问时自动解包，便于 v-model:plaintext="demo.plaintext"
  return reactive({
    plaintext,
    keyInfo,
    keyStatus,
    loading,
    logs,
    logText,
    replay,
    loadKey,
    sendNewRequest,
    replayLast
  })
}
