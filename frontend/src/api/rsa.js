/* ============================================================
   RSA 实验室 API（v1~v5 同前缀、分版本路径）
   ============================================================ */
import { request } from './http'

export function fetchPublicKey (version) {
  return request(`/api/rsa/${version}/key`)
}

/** raw：失败时仍可拿到错误文案（v5 防重放演示） */
export function secureEcho (version, payload) {
  return request(`/api/rsa/${version}/secure/echo`, {
    method: 'POST',
    body: payload,
    raw: true
  })
}
