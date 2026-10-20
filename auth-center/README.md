# Auth Center

认证中心的 P1 服务。进程能完成 OIDC 上游登录、授权码 + PKCE，以及 access / refresh token 签发。

## 已完成的任务

- **P1-AC-01** Go 1.23、Chi、`/healthz` 与 `/readyz`、结构化日志。
- **P1-INF-01** PostgreSQL 迁移（客户端、用户、身份源）和 §5.3.1 的 Redis 键读写。`auth:rt:{hash}` 的 TTL 由调用方传入，等于该客户端的 `refresh_token_ttl`。
- **P1-AC-02** OIDC 上游接到 `GET /oauth2/authorize`、上游登录和 `/idp/{id}/callback`。回调拿到工号后按非空属性更新用户，并创建全局会话。
- **P1-AC-03** 首次插入用户时授予 `default:viewer`（全局只读，`data_scope` 为 `self`）。再次登录不补授。空属性不覆盖已有值。
- **P1-AC-04** 授权码只接受 PKCE S256。`POST /oauth2/token` 签发 `at+jwt`（RS256 / ES256）和不透明 refresh token。无密钥的 web / app / miniapp 在授权码和刷新时可以不带 `client_secret`。ssr、m2m 以及配了密钥的客户端必须认证。刷新滑动轮换；重放旧 refresh token 吊销整条会话链并返回 `AUTH_REFRESH_REUSED`。公开客户端同样轮换并检测重放。
- **P1-AC-05** `/.well-known/openid-configuration` 与 `GET /oauth2/jwks`（`Cache-Control: max-age=600`）。启动时拒绝 `conformance/keys` 里的测试密钥。access token 使用客户端覆盖，否则用配置里的全局默认，并截断到 `access_token_ttl_cap`。
- **P1-AC-06** 刷新时同时检查空闲超时、绝对时长和当前 refresh token 的 TTL，先到期者返回 `AUTH_LOGIN_REQUIRED`。
- **P1-AC-07** 上游登录成功和失败按 `audit-event.schema.json` 追加进 PostgreSQL `audit_events`。不记录 token、密码、邮箱或姓名。写审计失败不拒绝登录。ES 或 ClickHouse 仍不代选。
- **P1-ADM-01** `POST/GET/PATCH /api/v1/apps` 与 `POST /api/v1/apps/{client_id}/secret`。密钥 bcrypt 入库，只在注册和轮换时返回一次。未填的有效期等于 §5.2 全局默认。管理页面未做，Vue3 或 React 仍不代选。
- **P1-DOC-01** 试点登录说明在 [`docs/pilot-login.md`](../docs/pilot-login.md)。
- **P4-BUS-01** `EventBus` 接口和本机房 Redis Stream 的 XADD / XRANGE。没有保留期裁剪，也没有写到其他机房。

另外已挂上设计 §5.4 的四个端点，它们还不是某条 P1 任务的全部验收：

- `GET /oauth2/logout`：RP-Initiated Logout。结束全局会话，向登记了 `backchannel_logout_uri` 的应用 POST `logout_token`，并发布 `auth.revoked`（`type=session`，`reason=logout`）。`post_logout_redirect_uri` 与 `redirect_uris` 精确匹配。上游登出仍不支持（R1）。没有跳转地址时返回 204。
- `GET /oauth2/userinfo`：Bearer `at+jwt`。空的可选字段不返回。
- `POST /oauth2/revoke`：RFC 7009。结束对应应用会话，不结束整个全局会话。公开客户端只能吊销自己的 token。发布 `auth.revoked`（`type=app_session`，`reason=logout`）。未知 token 返回 200。
- `POST /oauth2/introspect`：RFC 7662。只接受机密客户端。只能看到属于自己的 token。

refresh token 重放在吊销整条链之后再发布 `auth.revoked`（`type=session`，`reason=refresh_reused`）。P4-AC-04 的上游登出、SAML / CAS 以及管理端踢下线还没做。

试点可以通过文档里的 API 注册客户端并完成 OIDC 登录。管理后台页面还没有，因为前端框架未选。`client_credentials`、token exchange、CAS / SAML 不在本服务里。内省的「仅内网」没有在进程里做网络限制。

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

环境变量覆盖同名配置，例如 `AUTH_CENTER_ISSUER`、`AUTH_CENTER_POSTGRES_DSN`、`AUTH_CENTER_KEY_ACTIVE_PEM_FILE`、`AUTH_CENTER_USER_ACCESS_TOKEN_TTL`、`AUTH_CENTER_ADMIN_TOKEN`。设置了 active PEM 环境变量时，不再使用文件里的 `keys`。设置了 `AUTH_CENTER_IDP_ID` 时，不再使用文件里的 `idps`。引导令牌不要写进 YAML，启动日志也不打印它。为空时 `/api/v1/apps` 返回 401。

签名私钥只从 PEM 文件读取。`keys[].pem_file` 或 `AUTH_CENTER_KEY_ACTIVE_PEM_FILE` 指向文件；下一把用 `AUTH_CENTER_KEY_NEXT_PEM_FILE`，可选 `AUTH_CENTER_KEY_ACTIVE_KID`、`AUTH_CENTER_KEY_ACTIVE_ALG`、`AUTH_CENTER_KEY_NEXT_KID`、`AUTH_CENTER_KEY_NEXT_ALG`。Kubernetes 把 Secret 挂到这个路径。KMS 延后到 P7，当前不接。

全局默认有效期的内置数字在 `internal/config/lifetimes.go`（设计 §5.2）。YAML 和环境变量可以改这些默认；客户端 `session_policy` 里写了的项优先，access token 仍会被 `access_token_ttl_cap` 截断。ssr 使用 web 的空闲和绝对时长，miniapp 使用 app 的。没有单独的 ssr / miniapp 配置项。

上游只实现 OIDC。一个身份源时可以直接登录；多个身份源必须带 `idp_hint`。还没有身份源选择页。回调路径是 `/idp/{id}/callback`。

令牌端点接受 `client_secret_basic` 和 `client_secret_post`。`client_secret` 以 bcrypt 保存。没有密钥的 web、app、miniapp 在 `authorization_code` 和 `refresh_token` 上只交 `client_id`。交了密钥就必须匹配，否则 `invalid_client`。ssr 和 m2m 即使没配密钥也不能免认证。refresh token 在 Redis 里的键是原始值的 SHA-256 十六进制，不是原始 token。

新用户第一次登录获得角色 `default:viewer`。删掉这条绑定后，再次登录不会再授。
