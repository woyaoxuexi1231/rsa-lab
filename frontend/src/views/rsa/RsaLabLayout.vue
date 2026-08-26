<!-- RSA 实验室：v1~v5 分段导航 -->
<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import SegmentedNav from '../../components/SegmentedNav.vue'

const route = useRoute()
const router = useRouter()

const demoItems = [
  { value: '/rsa/v1', label: '1️⃣ 最小闭环' },
  { value: '/rsa/v2', label: '2️⃣ 响应签名' },
  { value: '/rsa/v3', label: '3️⃣ CBC+IV' },
  { value: '/rsa/v4', label: '4️⃣ 密钥版本' },
  { value: '/rsa/v5', label: '5️⃣ 防重放' }
]

const activeDemo = computed(() =>
  demoItems.some(i => i.value === route.path) ? route.path : demoItems[0].value
)

function goDemo (path) {
  router.push(path)
}
</script>

<template>
  <div class="rsa-layout">
    <SegmentedNav
      :items="demoItems"
      :model-value="activeDemo"
      class="rsa-layout__nav"
      @change="goDemo"
    />
    <router-view/>
  </div>
</template>

<style scoped>
.rsa-layout__nav {
  margin: var(--space-6) 0;
  flex-wrap: wrap;
}
</style>
