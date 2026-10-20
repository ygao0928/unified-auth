# Access Token 校验算法

所有 SDK（Go / Python / Java / JS 后端）以及网关插件**必须**严格按照本文的步骤和顺序校验 Access Token。

一个 token 同时有多处缺陷时，**以最先失败的那一步对应的错误码为准**，这样三端返回的错误码才能完全一致。一致性测试用例见 [`conformance/`](../conformance/)。

## 输入

| 参数 | 说明 |
|---|---|
| `token` | 从 `Authorization: Bearer <token>` 中取出的字符串；BFF 模式下从服务端会话中取出 |
| `config.issuer` | 认证中心的 issuer，例如 `https://auth.corp.com` |
| `config.client_id` | 本应用的 client_id |
| `config.clock_skew` | 允许的时钟偏差，单位秒，默认 `60`，最大 `300` |
| `jwks` | 认证中心的公钥集合（本地缓存） |
| `revocations` | 本地吊销集合（见下文"吊销匹配"） |
| `now` | 当前时间，Unix 秒。**SDK 必须支持注入时钟**，以便运行一致性测试 |

## 校验步骤

| 步骤 | 检查内容 | 失败时的错误码 |
|---|---|---|
| 1 | token 为空或不存在 | `AUTH_TOKEN_MISSING` |
| 2 | 是合法的 JWS Compact 格式：三段 base64url，头部是 JSON 对象 | `AUTH_TOKEN_INVALID` |
| 3 | 头部 `typ` 等于 `at+jwt` 或 `application/at+jwt`（不区分大小写） | `AUTH_TOKEN_INVALID` |
| 4 | 头部 `alg` 在白名单 `RS256`、`ES256` 内。**`none`、`HS*` 一律拒绝** | `AUTH_TOKEN_INVALID` |
| 5 | 头部 `kid` 存在，并且能在 JWKS 中找到对应的密钥；该密钥的 `kty` 与 `alg` 匹配（`RS256` 对应 `RSA`，`ES256` 对应 `EC`/`P-256`）。找不到时，按"JWKS 缓存"规则刷新**一次**后再查找 | `AUTH_TOKEN_INVALID` |
| 6 | 签名验证通过 | `AUTH_TOKEN_INVALID` |
| 7 | payload 是 JSON 对象；必填 claims 都存在且类型正确（见下表） | `AUTH_TOKEN_INVALID` |
| 8 | `iss` 与 `config.issuer` **完全相等**（区分大小写，不做尾部斜杠归一化） | `AUTH_TOKEN_INVALID` |
| 9 | `now > exp + clock_skew` 时判定为过期 | `AUTH_TOKEN_EXPIRED` |
| 10 | 存在 `nbf` 且 `now + clock_skew < nbf`；或者 `now + clock_skew < iat` | `AUTH_TOKEN_INVALID` |
| 11 | `aud` 为字符串时等于 `config.client_id`；为数组时包含 `config.client_id` | `AUTH_AUDIENCE_MISMATCH` |
| 12 | 没有命中本地吊销集合（见"吊销匹配"） | `AUTH_SESSION_REVOKED` |

全部通过后，按"输出 User"的规则构造用户对象。

### 必填 claims

| claim | 类型 | 条件 |
|---|---|---|
| `iss` | string | 始终必填 |
| `sub` | string，非空 | 始终必填。用户 token 中为工号；`m2m` token 中为 `client:<client_id>` |
| `aud` | string 或 string[] | 始终必填 |
| `exp` | integer | 始终必填 |
| `iat` | integer | 始终必填 |
| `jti` | string，非空 | 始终必填 |
| `azp` | string，非空 | 始终必填 |
| `client_type` | string，取值为 `web`/`ssr`/`app`/`miniapp`/`m2m` 之一 | 始终必填 |
| `perm_ver` | integer，≥ 0 | 始终必填 |
| `sid` | string，非空 | `client_type` 不是 `m2m` 时必填 |
| `asid` | string，非空 | `client_type` 不是 `m2m` 时必填 |

其余 claims（`name`、`email`、`dept_id`、`dept_name`、`scope`、`amr`、`auth_time`、`nbf`）都是可选的：

- 出现时必须是正确的类型，否则按步骤 7 返回 `AUTH_TOKEN_INVALID`。
- 可选字符串字段的值为空字符串时，**视同不存在**。
- SDK **必须**忽略所有不认识的 claims。

## 吊销匹配

本地吊销集合由 `auth.revoked` 事件构成，事件格式见 [`schemas/revocation-event.schema.json`](schemas/revocation-event.schema.json)。只要 token 命中下面**任意一条**规则，就判定为已吊销：

| 事件 `type` | 命中条件 |
|---|---|
| `session` | `event.sid == token.sid` |
| `app_session` | `event.asid == token.asid` |
| `user` | `event.sub == token.sub` 且 `token.iat < event.not_before` |
| `client` | `event.client_id == token.azp` 或 `event.client_id` 在 `token.aud` 中，且 `token.iat < event.not_before` |

说明：
- `user` 和 `client` 类型使用 `not_before` 判断，所以吊销之后**重新签发**的 token 不受影响。例如用户被强制下线后重新登录，新 token 可以正常使用。
- 每条吊销记录在本地保存到 `event.ts + access_token_ttl_cap + clock_skew` 为止，之后可以清理。`access_token_ttl_cap` 是认证中心配置的 access token 有效期上限，默认 1800 秒；任何客户端的有效 access token 时长都不得超过它，所以到这个时间点，受影响的 token 都已经自然过期。`clock_skew` 默认 60 秒，默认一共保留 1860 秒。SDK 的 `revocation.retention` 不得小于该值。

## JWKS 缓存

1. SDK 启动时从 `{issuer}/oauth2/jwks` 拉取公钥（也可以从 discovery 文档中的 `jwks_uri` 获取地址）。
2. 定时刷新，默认间隔 10 分钟。
3. 遇到未知的 `kid` 时立即刷新一次。两次这类刷新之间至少间隔 30 秒，防止攻击者用随机 `kid` 打满认证中心。
4. 刷新失败时**继续使用已缓存的密钥**并上报告警，不能因为刷新失败就拒绝所有请求。
5. 启动时如果一次都没能拉取成功，所有请求返回 `AUTH_DEPENDENCY_UNAVAILABLE`。

## 输出 User

结构见 [`schemas/user.schema.json`](schemas/user.schema.json)：

| User 字段 | 来源 |
|---|---|
| `emp_no` | `sub`（`m2m` 时为 `null`） |
| `subject` | `sub` |
| `is_machine` | `client_type == "m2m"` |
| `name` / `email` / `dept_id` / `dept_name` | 同名 claim；不存在或为空字符串时为 `null` |
| `client_id` | `azp` |
| `client_type` | `client_type` |
| `sid` / `asid` | 同名 claim；`m2m` 时为 `null` |
| `scopes` | `scope` 按空格拆分得到的数组；不存在时为 `[]` |
| `perm_ver` | `perm_ver` |
| `amr` | `amr`；不存在时为 `[]` |
| `auth_time` | `auth_time`；不存在时为 `null` |
| `token_id` | `jti` |
| `expires_at` | `exp` |
