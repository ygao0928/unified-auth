# 试点登录

试点项目按这篇文档配置认证中心、注册客户端，并走完 OIDC 授权码登录。应用注册页面在 [`admin-ui/`](../admin-ui/README.md)，用 React、TypeScript、Vite 和 Ant Design。也可以直接调用下面的 HTTP API。

## 认证中心

进程需要 PostgreSQL、Redis，以及一把 RS256 或 ES256 私钥文件。示例见 [`auth-center/config.example.yaml`](../auth-center/config.example.yaml)。

```bash
cd auth-center
export AUTH_CENTER_CONFIG=$PWD/config.example.yaml
export AUTH_CENTER_ADMIN_TOKEN='替换成引导令牌'
make keygen
make build
./bin/auth-center
```

`issuer` 对内外网是同一个值。上游回调必须登记在身份源上，路径是 `{issuer}/idp/{id}/callback`，没有尾部斜杠。

## OIDC 上游

P1 只接 OIDC。CAS 和 SAML 在 P6。只配一个身份源时，`/oauth2/authorize` 会直接跳过去。多个身份源且没有 `idp_hint` 时，授权端点返回选择页（中文或英文），授权请求已经保存在事务里，选定后跳到对应上游。`idp_hint` 命中则跳过选择页。未知的 `idp_hint` 仍回到应用并带 `invalid_request`。选择页不在管理后台里。`display_name` 是选择页上的名称，不填时用身份源 id。语言先看 `ui_locales`，再看 `Accept-Language`，都没有则用中文。

YAML：

```yaml
idps:
  - id: corp-oidc
    protocol: OIDC
    display_name: 公司账号
    issuer: https://idp.example.com
    client_id: auth-center
    client_secret: 替换成上游密钥
    redirect_url: https://auth.example.com/idp/corp-oidc/callback
    scopes: [openid]
    attribute_mapping:
      emp_no: employeeNumber
      name: name
      email: email
```

`emp_no` 映射的 claim 必须有值，这是工号。姓名、邮箱、手机号、部门为空时不覆盖已有值。

环境变量会替换整个 `idps` 列表：

```bash
export AUTH_CENTER_IDP_ID=corp-oidc
export AUTH_CENTER_IDP_ISSUER=https://idp.example.com
export AUTH_CENTER_IDP_CLIENT_ID=auth-center
export AUTH_CENTER_IDP_CLIENT_SECRET=替换成上游密钥
export AUTH_CENTER_IDP_REDIRECT_URL=https://auth.example.com/idp/corp-oidc/callback
export AUTH_CENTER_IDP_SCOPES='openid'
export AUTH_CENTER_IDP_EMP_NO_CLAIM=employeeNumber
```

签名私钥用 `AUTH_CENTER_KEY_ACTIVE_PEM_FILE`，或 YAML 里的 `keys[].pem_file`。Kubernetes 把 Secret 挂到这个路径。KMS 延后到 P7。

## 注册应用

`client_credentials` 还没做。在此之前，`Authorization: Bearer` 使用 `AUTH_CENTER_ADMIN_TOKEN`，或者一枚 `typ=at+jwt`、`client_type=m2m`、scope 含 `ua.apps.register` 的 access token。

```bash
curl -sS -D- https://auth.example.com/api/v1/apps \
  -H "Authorization: Bearer $AUTH_CENTER_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "会议",
    "client_type": "web",
    "redirect_uris": ["https://meeting.example.com/auth/callback"],
    "backchannel_logout_uri": "https://meeting.example.com/backchannel-logout"
  }'
```

201 响应里的 `client_secret` 只出现这一次，库里只存 bcrypt。之后 `GET /api/v1/apps/{client_id}` 不再返回它。轮换用 `POST /api/v1/apps/{client_id}/secret`，新密钥同样只展示一次。

`web`、`app`、`miniapp` 可以传 `"public": true`，这时不生成密钥。授权码已经用 PKCE S256 时，换票和刷新只带 `client_id`。`ssr` 和 `m2m` 不能公开，总会得到密钥，换票必须认证。带了密钥就必须和哈希一致。

除 `m2m` 外，至少要有一个绝对 `redirect_uri`，授权和登出回跳都按这个列表精确匹配。`backchannel_logout_uri` 可空；有值时，全局登出会向它 POST `logout_token`。

`session_policy` 只写要覆盖的秒数。没写的项等于下面的全局默认。用户 access token 再被 `access_token_ttl_cap`（默认 1800）截断。

| 客户端类型 | access_token_ttl | refresh_token_ttl | idle_timeout | absolute_session_ttl |
|---|---|---|---|---|
| web / ssr | 600 | 600 | 7200 | 43200 |
| app / miniapp | 600 | 600 | 604800 | 2592000 |
| m2m | 1800 | 不签发 | — | — |

## 浏览器登录

`GET /oauth2/authorize` 只接受 `response_type=code` 和 `code_challenge_method=S256`。`scope` 必须包含 `openid`。`state` 长度 16 到 1024。`redirect_uri` 与注册值精确匹配。

已有 `auth_sid` cookie 时直接发授权码，不再记一次新的登录审计。没有会话时跳上游，回调成功后创建全局会话。

换票：

```bash
curl -sS https://auth.example.com/oauth2/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=authorization_code \
  -d code="$CODE" \
  -d redirect_uri='https://meeting.example.com/auth/callback' \
  -d code_verifier="$VERIFIER"
```

公开客户端去掉 `-u`，改为 `-d client_id=...`。响应里的 access token 是 `at+jwt`。`refresh_token` 不透明。每次刷新都轮换，新的 refresh token 从当时起重新计算 `refresh_token_ttl`（默认 600 秒）。在这 600 秒内持续轮换，会话可以延续到空闲超时或绝对时长，先到期者返回 `AUTH_LOGIN_REQUIRED`。重放旧 refresh token 吊销整条会话链并返回 `AUTH_REFRESH_REUSED`。客户端认证失败返回 HTTP 401，`code` 为 `INVALID_CLIENT`。

授权码默认 60 秒（`auth_code_ttl`），授权事务默认 600 秒（`authorize_txn_ttl`）。这两项是认证中心进程配置，不能按应用覆盖。环境变量是 `AUTH_CENTER_AUTH_CODE_TTL` 和 `AUTH_CENTER_AUTHORIZE_TXN_TTL`。

## 登出

`GET /oauth2/logout` 结束全局会话。`post_logout_redirect_uri` 必须落在该客户端的 `redirect_uris` 里，成功时 302。没有这个地址、上游又不支持登出时返回 204。当前 OIDC 适配器不支持上游登出。

## 这一阶段没有

- `client_credentials`、token exchange、`private_key_jwt`
- CAS / SAML 上游
- 管理员二次认证
- 审计的长期存储（ES 或 ClickHouse 未选）
