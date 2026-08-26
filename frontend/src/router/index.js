import { createRouter, createWebHashHistory } from 'vue-router'

const routes = [
  { path: '/', component: () => import('../views/home/HomePage.vue') },
  {
    path: '/rsa',
    component: () => import('../views/rsa/RsaLabLayout.vue'),
    redirect: '/rsa/v1',
    children: [
      { path: 'v1', component: () => import('../views/rsa/demos/V1Demo.vue') },
      { path: 'v2', component: () => import('../views/rsa/demos/V2Demo.vue') },
      { path: 'v3', component: () => import('../views/rsa/demos/V3Demo.vue') },
      { path: 'v4', component: () => import('../views/rsa/demos/V4Demo.vue') },
      { path: 'v5', component: () => import('../views/rsa/demos/V5Demo.vue') }
    ]
  }
]

const router = createRouter({
  history: createWebHashHistory(import.meta.env.VITE_APP_BASE),
  routes
})

export default router
