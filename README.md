# call-auth

单点登录的认证中心。**唯一能签发身份的服务**，其他服务（call-back、learn-daily）
只拿公钥验签、不签发。

设计与取舍的完整说明在 `call-back/认证中心设计文档.md`。本文件只讲怎么跑和怎么验。

## 跑起来

```bash
cd call-auth
cp .env.example .env     # 填数据库配置；私钥路径保持默认即可
go run .                 # 监听 :8020
```

首次启动会自动生成 RS256 密钥对到 `keys/private.pem`（0600，已 gitignore）。
**生产上如果启动日志里出现「已生成新密钥」，要立刻查** —— 那说明路径配错了或
文件被删了，而换密钥会让所有已发出的 token 立刻失效。

数据库指向 **call-back 的库**：`users` 表是身份权威源，它的 id 被所有业务表当外键
引用，搬走要改遍全库外键（设计文档 §4.4）。call-auth 只读它，以及建自己的一张表。

## 接口

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| POST | `/api/v1/auth/register` | 否 | 注册并直接返回登录态 |
| POST | `/api/v1/auth/login` | 否 | 登录 |
| POST | `/api/v1/auth/refresh` | 否 | 用 refresh token 换新的一对（轮换 + 重放检测） |
| POST | `/api/v1/auth/logout` | 否 | 登出。`?all_devices=true` 登出全部设备 |
| GET | `/api/v1/auth/me` | 是 | 当前用户信息 |
| GET | `/.well-known/jwks.json` | 否 | 公钥集（标准 JWKS） |
| GET | `/health` | 否 | 探活 |

响应统一是 `{code, message, error, data}`。`error` 是**给程序看的**标识
（`token_reuse_detected`、`token_invalid`、`username_taken`…），前端靠它决定行为，
不要去匹配中文 message。

## 验

```bash
go test ./...            # 单测：密钥、JWT、轮换、重放、注册登录
go run ./scripts/verify  # 打真服务的端到端自验证（34 项）
```

`scripts/verify` 是**站在资源服务的立场**跑的：它只从 JWKS 取公钥、绝不接触私钥，
然后独立验证签发出来的 token。这正是整个方案要保证的性质。

注意它会往库里写一个 `verify_<时间戳>` 的测试账号，跑完记得清。

## 与设计文档的两处偏离

1. **表名带前缀**：文档里叫 `refresh_tokens`，实现是 `auth_refresh_tokens`。
   本服务与 call-back 共库，前缀让「谁拥有哪张表」一目了然。

2. **登出不需要 access token**：文档 §6.4 写的是需要 `Authorization` + 可选
   `refresh_token`。实现改成只认 `refresh_token`。原因是 access token 只有 15 分钟，
   要求它的话，用户放着不管半小时后想登出会先收到 401 —— 而登出恰恰是登录态
   不对劲时最需要能用的操作。refresh token 本身就能定位到用户。

## 尚未实现

- SSO 票据交换（`/sso` + `/auth/ticket`）—— 跨应用静默登录，设计文档 §6.7/§6.8
- 登录限流（连续失败锁定）
- 密钥轮换时的多公钥并存（JWKS 结构已经留好，`kid` 也已按公钥内容派生）
- `users` 表的写入权限收拢（需要先改 call-back，见下）

## 下一步

call-back 目前还在用自己的 HS256（`utils/jwt.go` 已经先修好了 token 永不过期的
问题，但没有接本服务）。要接入需要：

1. call-back 的 `ParseToken` 换成 RS256 公钥验签（拉 JWKS + 按 kid 缓存）
2. 删掉 call-back 的 `/auth/login`、`/auth/register` 和所有 users 表写入
3. 前端登录页改指向本服务

按设计文档，这是 M3 的内容。
