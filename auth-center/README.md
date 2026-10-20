# Auth Center

认证中心的 P1 骨架。进程能启动，并带上后面登录流程要依赖的基础件。授权码、刷新和 token 签发还没有接上。

## 已完成的任务

- **P1-AC-01** Go 1.23、Chi、`/healthz` 与 `/readyz`、结构化日志。
- **P1-INF-01** PostgreSQL 迁移（客户端、用户、身份源）和 §5.3.1 的 Redis 键读写。`auth:rt:{hash}` 的 TTL 由调用方传入，等于该客户端的 `refresh_token_ttl`。

## 只搭了骨架

- **P1-AC-02** `IdentityProvider` 与 OIDC 适配器。`Discover` 之后能拼登录跳转并交换 code，但没有接到 `/oauth2/authorize`，也没有真实上游的集成测试。
- **P1-AC-05** 加载签名密钥、拒绝 `conformance/keys` 里的测试密钥、`GET /oauth2/jwks`（`Cache-Control: max-age=600`）。不签发 access token，也没有 discovery 文档。
- **P4-BUS-01** `EventBus` 接口和本机房 Redis Stream 的 XADD / XRANGE。没有保留期裁剪，也没有写到其他机房。

未完成：P1-AC-03、P1-AC-04、P1-AC-06、P1-AC-07、P1-ADM-01、P1-DOC-01。用户落库时「空属性不覆盖」已经有仓储方法，默认角色还没有。

## 本地

```bash
cd auth-center
make test
make keygen
make build
```

`AUTH_CENTER_TEST_DSN` 指向 PostgreSQL 时会跑迁移和仓储测试；没设置就跳过。

```bash
export AUTH_CENTER_CONFIG=$PWD/config.example.yaml
make keygen
./bin/auth-center
```

依赖本机或 `make up` 里的 PostgreSQL 和 Redis。`make up` 需要 Docker。开发密钥写到 `.dev-keys/active.pem`，不要拿到生产环境用。

环境变量覆盖同名配置，例如 `AUTH_CENTER_ISSUER`、`AUTH_CENTER_POSTGRES_DSN`、`AUTH_CENTER_KEY_ACTIVE_PEM_FILE`。设置了 active PEM 环境变量时，不再使用文件里的 `keys`。

全局默认有效期写死在 `internal/config/lifetimes.go`（设计 §5.2）。进程配置只能改 `access_token_ttl_cap`、`previous_key_buffer` 和 `clock_skew`。客户端覆盖放在 `clients.session_policy`。
