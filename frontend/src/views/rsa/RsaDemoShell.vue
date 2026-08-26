<script setup>
import PageHeader from '../../components/PageHeader.vue'
import StatusBar from '../../components/StatusBar.vue'
import FormField from '../../components/FormField.vue'
import AppButton from '../../components/AppButton.vue'
import CodeBlock from '../../components/CodeBlock.vue'

defineProps({
  title: { type: String, required: true },
  subtitle: String,
  problem: String,
  solution: String,
  plaintext: { type: String, required: true },
  keyStatus: { type: String, required: true },
  keyHint: String,
  loading: Boolean,
  logText: String,
  hasLogs: Boolean,
  replay: Boolean
})

const emit = defineEmits(['update:plaintext', 'send', 'replay', 'reload'])

function onPlaintext (v) {
  emit('update:plaintext', v)
}
</script>

<template>
  <div class="rsa-demo">
    <PageHeader :title="title" :subtitle="subtitle"/>

    <div v-if="problem || solution" class="rsa-demo__story">
      <p v-if="problem"><span class="rsa-demo__tag rsa-demo__tag--warn">❓ 问题</span>{{ problem }}</p>
      <p v-if="solution"><span class="rsa-demo__tag rsa-demo__tag--ok">✅ 本版</span>{{ solution }}</p>
    </div>

    <StatusBar
      :variant="keyStatus === 'ready' ? 'success' : keyStatus === 'error' ? 'error' : 'info'"
      class="rsa-demo__status"
    >
      <template v-if="keyStatus === 'ready'">🔑 {{ keyHint || '公钥已加载' }}</template>
      <template v-else-if="keyStatus === 'error'">❌ 公钥加载失败 — 请确认 rsa-lab 后端已启动</template>
      <template v-else>⏳ 正在加载公钥...</template>
    </StatusBar>

    <div class="rsa-demo__form">
      <FormField
        :model-value="plaintext"
        label="🔒 敏感数据"
        placeholder="要加密的明文"
        @update:model-value="onPlaintext"
      />
      <div class="rsa-demo__actions">
        <AppButton :loading="loading" :disabled="keyStatus !== 'ready'" @click="emit('send')">
          📤 发送新请求
        </AppButton>
        <AppButton
          v-if="replay"
          variant="warning"
          :loading="loading"
          :disabled="keyStatus !== 'ready'"
          @click="emit('replay')"
        >
          🔁 重放上一包
        </AppButton>
        <AppButton variant="secondary" :disabled="loading" @click="emit('reload')">
          🔄 刷新公钥
        </AppButton>
      </div>
    </div>

    <div class="rsa-demo__logs">
      <h2 class="rsa-demo__logs-title">📜 执行日志</h2>
      <CodeBlock v-if="hasLogs">{{ logText }}</CodeBlock>
      <p v-else class="rsa-demo__empty">📭 暂无日志</p>
    </div>
  </div>
</template>

<style scoped>
.rsa-demo {
  max-width: var(--container-narrow);
}
.rsa-demo__story {
  margin-bottom: var(--space-5);
  font-size: var(--font-sm);
  color: var(--color-text-secondary);
  letter-spacing: var(--tracking-body);
  line-height: 1.7;
}
.rsa-demo__story p + p {
  margin-top: var(--space-3);
}
.rsa-demo__tag {
  display: inline-block;
  margin-right: var(--space-2);
  font-size: var(--font-xs);
  letter-spacing: var(--tracking-label);
  padding: 0 var(--space-1);
  border: 1px solid;
  border-radius: var(--radius-sm);
}
.rsa-demo__tag--warn {
  color: var(--color-warning);
  border-color: var(--color-warning);
  background: var(--color-warning-bg);
}
.rsa-demo__tag--ok {
  color: var(--color-success);
  border-color: var(--color-success);
  background: var(--color-success-bg);
}
.rsa-demo__status {
  margin-bottom: var(--space-5);
}
.rsa-demo__form {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  margin-bottom: var(--space-6);
}
.rsa-demo__actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
}
.rsa-demo__logs-title {
  font-size: var(--font-md);
  font-weight: var(--weight-medium);
  letter-spacing: var(--tracking-label);
  margin-bottom: var(--space-2);
}
.rsa-demo__empty {
  font-size: var(--font-sm);
  color: var(--color-text-muted);
}
</style>
