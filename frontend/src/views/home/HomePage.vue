<script setup>
import PageHeader from '../../components/PageHeader.vue'
import AppCard from '../../components/AppCard.vue'
</script>

<template>
  <div class="home">
    <PageHeader
      title="RSA 混合加密实验室"
      subtitle="从最小闭环到防重放：v1 → v5 对照试跑"
    />
    <div class="home__grid">
      <router-link to="/rsa/v1" class="home__link">
        <AppCard clickable shadow>
          <h2 class="home__title">1️⃣ 最小闭环</h2>
          <p class="home__desc">RSA-PKCS1 包 AES key + AES-ECB，跑通混合加密。</p>
        </AppCard>
      </router-link>
      <router-link to="/rsa/v2" class="home__link">
        <AppCard clickable shadow>
          <h2 class="home__title">2️⃣ 响应签名</h2>
          <p class="home__desc">SHA256withRSA 签响应密文，防止篡改。</p>
        </AppCard>
      </router-link>
      <router-link to="/rsa/v3" class="home__link">
        <AppCard clickable shadow>
          <h2 class="home__title">3️⃣ CBC + IV</h2>
          <p class="home__desc">AES-CBC 替代 ECB，签名覆盖 iv \|\| 密文。</p>
        </AppCard>
      </router-link>
      <router-link to="/rsa/v4" class="home__link">
        <AppCard clickable shadow>
          <h2 class="home__title">4️⃣ 密钥版本</h2>
          <p class="home__desc">多版本密钥 + 短时 token，防降级攻击。</p>
        </AppCard>
      </router-link>
      <router-link to="/rsa/v5" class="home__link">
        <AppCard clickable shadow>
          <h2 class="home__title">5️⃣ 防重放</h2>
          <p class="home__desc">timestamp + nonce + HMAC，拒绝重放包。</p>
        </AppCard>
      </router-link>
    </div>
  </div>
</template>

<style scoped>
.home__grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: var(--space-4);
  margin-top: var(--space-6);
}
.home__link {
  color: inherit;
  text-decoration: none;
}
.home__title {
  font-size: var(--font-lg);
  margin-bottom: var(--space-2);
}
.home__desc {
  font-size: var(--font-sm);
  color: var(--color-text-secondary);
  line-height: 1.55;
}
</style>
