# RSA Lab

从 Study Hub 抽离的 RSA 混合加密学习实验室：后端 Spring Boot 提供 v1→v5 API，前端 Vue 对照试跑。

## 目录结构

```text
rsa-lab/
├── backend/     # Spring Boot（:8086）
└── frontend/    # Vue 3 + Vite
```

## 版本一览

| 版本 | 前缀 | 学习点 |
|---|---|---|
| v1 | `/api/rsa/v1` | RSA-PKCS1 包 AES key + AES-ECB，无签名 |
| v2 | `/api/rsa/v2` | 响应 `SHA256withRSA` 签名 + 前端验签 |
| v3 | `/api/rsa/v3` | AES-CBC + IV，签名覆盖 `iv \|\| ciphertext` |
| v4 | `/api/rsa/v4` | 多版本密钥 + keyVersion 绑定 token |
| v5 | `/api/rsa/v5` | timestamp + nonce + HMAC 防重放 |

每个版本：`GET /api/rsa/v{n}/key`、`POST /api/rsa/v{n}/secure/echo`。

## 后端

```powershell
cd backend
mvn spring-boot:run
```

- 端口：`http://localhost:8086`
- API 前缀：`/api/rsa/**`

## 前端

```powershell
cd frontend
npm install
npm run dev
```

浏览器打开 <http://127.0.0.1:13006/> 。

## 来源

原位于 [study-hub](https://github.com/woyaoxuexi1231/study-hub) 的 `rsa-lab` 模块，现独立维护。
