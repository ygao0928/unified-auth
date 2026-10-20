# Auth Center

认证中心的 P1 服务。进程能完成 OIDC 上游登录、授权码 + PKCE，以及 access / refresh token 签发。

## 已完成的任务

- **P1-AC-01** Go 1.23、Chi、`/healthz` 与 `/readyz`、结构化日志。
- **P1-INF-01** PostgreSQL 迁移（客户端、用户、身份源）和 §5.3.1 的 Redis 键读写。`auth:rt:{hash}` 的 TTL 由调用方传入，等于该客户端的 `refresh_token_ttl`。
- **P1-AC-02** OIDC 上游接到 `GET /oauth2/authorize`、上游登录和 `/idp/{id}/callback`。回调拿到工号后按非空属性更新用户，并创建全局会话。
- **P1-AC-04** 授权码只接受 PKCE S256。`POST /oauth2/token` 签发 `at+jwt`（RS256 / ES256）和不透明 refresh token。刷新滑动轮换；重放旧 refresh token 吊销整条会话链并返回 `AUTH_REFRESH_REUSED`。
- **P1-AC-05** `/.well-known/openid-configuration` 与 `GET /oauth2/jwks`（`Cache-Control: max-age=600`）。启动时拒绝 `conformance/keys` 里的测试密钥。access token 使用客户端覆盖，否则用配置里的全局默认，并截断到 `access_token_ttl_cap`。
- **P1-AC-06** 刷新时同时检查空闲超时、绝对时长和当前 refresh token 的 TTL，先到期者返回 `AUTH_LOGIN_REQUIRED`。
- **P4-BUS-01** `EventBus` 接口和本机房 Redis Stream 的 XADD / XRANGE。没有保留期裁剪，也没有写到其他机房。

未完成：P1-AC-03（默认角色仍未决定）、P1-AC-07、P1-ADM-01、P1-DOC-01。用户落库时「空属性不覆盖」已经生效。`client_credentials`、token exchange、CAS / SAML 不在本服务里。

## 本地

```bash
cd auth-center
make test
make keygen
make build
```

`AUTH_CENTER_TEST_DSN` 指向 PostgreSQL 时会跑迁移、仓储和 OIDC 流程测试；没设置就跳过依赖数据库的测试。签发的 access token 会用 `conformance/tools/reference.py` 做 12 步校验，需要本机有 `python3`、`PyJWT` 和 `cryptography`。

```bash
export AUTH_CENTER_CONFIG=$PWD/config.example.yaml
make keygen
./bin/auth-center
```

依赖本机或 `make up` 里的 PostgreSQL 和 Redis。`make up` 需要 Docker。开发密钥写到 `.dev-keys/active.pem`，不要拿到生产环境用。

环境变量覆盖同名配置，例如 `AUTH_CENTER_ISSUER`、`AUTH_CENTER_POSTGRES_DSN`、`AUTH_CENTER_KEY_ACTIVE_PEM_FILE`、`AUTH_CENTER_USER_ACCESS_TOKEN_TTL`。设置了 active PEM 环境变量时，不再使用文件里的 `keys`。设置了 `AUTH_CENTER_IDP_ID` 时，不再使用文件里的 `idps`。

全局默认有效期的内置数字在 `internal/config/lifetimes.go`（设计 §5.2）。YAML 和环境变量可以改这些默认；客户端 `session_policy` 里写了的项优先，access token 仍会被 `access_token_ttl_cap` 截断。ssr 使用 web 的空闲和绝对时长，miniapp 使用 app 的。没有单独的 ssr / miniapp 配置项。

上游只实现 OIDC。一个身份源时可以直接登录；多个身份源必须带 `idp_hint`。还没有身份源选择页。回调路径是 `/idp/{id}/callback`。

令牌端点接受 `client_secret_basic` 和 `client_secret_post`。`client_secret` 以 bcrypt 保存。refresh token 在 Redis 里的键是原始值的 SHA-256 十六进制，不是原始 token。
