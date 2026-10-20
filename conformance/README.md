# 一致性测试（conformance）

三端 SDK（Go / Python / Java）、网关插件，以及任何自行实现 token 校验的组件，**都必须通过本目录下的全部用例**，并把它们作为 CI 的强制门禁。

用例依据的规范：
- [`spec/token-validation.md`](../spec/token-validation.md)：Access Token 校验算法
- [`spec/authorization.md`](../spec/authorization.md)：权限匹配与数据范围规则

## 目录

```
conformance/
├── keys/
│   ├── jwks.json            初始 JWKS（rsa-1, rsa-2, ec-1）
│   ├── jwks-rotated.json    刷新后的 JWKS（额外包含 rsa-3，模拟密钥轮换）
│   └── *.private.pem        测试私钥，仅用于重新生成向量
├── vectors/
│   ├── token-cases.json     64 个 token 校验用例
│   └── authz-cases.json     30 个权限匹配与数据范围用例
└── tools/
    ├── generate.py          向量生成器
    ├── reference.py         参考实现（Python，仅用于对照，不是生产代码）
    └── run_reference.py     用参考实现运行全部用例，同时校验 spec 的 schema 和 OpenAPI
```

> ⚠️ `keys/*.private.pem` 是**公开的测试密钥**，绝不能用于任何真实环境。认证中心应当在启动时检查自己的签名密钥，如果其 `kid` 或公钥与这里的测试密钥相同，就拒绝启动。

## SDK 测试框架怎么写

### token-cases.json

```jsonc
{
  "now": 1792375200,                       // 测试用的固定时间，SDK 必须支持注入时钟
  "config": { "issuer": "...", "client_id": "meeting", "clock_skew": 60 },
  "jwks": { "initial": "../keys/jwks.json", "after_refresh": "../keys/jwks-rotated.json" },
  "cases": [
    {
      "id": "valid_full",
      "token": "eyJ...",                   // 可能为 null（表示请求未携带 token）
      "revocations": [ ... ],              // 可选：执行本用例前注入本地吊销集合的事件
      "expect": { "valid": true, "error": null, "user": { ... } }
    }
  ]
}
```

对**每一个**用例，测试框架按以下步骤执行：

1. **新建**一个校验器实例，各用例之间不能共享缓存和状态。
2. 将时钟固定为 `now`。
3. 用 `jwks.initial` 初始化 JWKS 缓存。把 JWKS 的拉取函数替换成桩：第一次刷新返回 `jwks.after_refresh`。同时关闭"未知 kid 刷新最小间隔"的限制，或者每个用例重置一次。
4. 如果用例有 `revocations`，把这些事件逐条注入本地吊销集合。
5. 调用校验函数，传入 `token`。
6. 断言结果：
   - `expect.valid == false` 时，返回的错误码必须**等于** `expect.error`。
   - `expect.valid == true` 时，SDK 输出的 User 转换成规范字段名（snake_case）后，必须与 `expect.user` **逐字段相等**，包括值为 `null` 和 `[]` 的字段。

### authz-cases.json

| 分组 | 输入 | 期望 |
|---|---|---|
| `has_perm` | `granted`（已授予权限点列表）、`required`（所需权限点） | `true` / `false` / `"programming_error"` |
| `combinations` | `granted`、`mode`（`all` / `any`）、`required`（列表） | 同上 |
| `data_scope` | `role_scopes`（各角色的数据范围，可含 `null`）、`dept_id` | 有效数据范围或 `null` |

`"programming_error"` 表示 SDK 必须抛出编程错误（异常或 panic），不能只返回 `false`。

## 维护

```bash
pip install pyjwt cryptography jsonschema pyyaml openapi-spec-validator
python3 conformance/tools/generate.py        # 修改用例后重新生成（默认复用已有测试密钥）
python3 conformance/tools/run_reference.py   # 必须输出 ALL PASSED
```

维护规则：
- 新增用例时，在 `generate.py` 中添加。**已发布用例的 `id` 不能修改，也不能复用。**
- 如果改了规范，必须同步修改 `reference.py`、对应的用例，以及规范文档，并且三者放在同一个 PR 中提交。
- 三端 SDK 在 CI 中引用本目录时，应当固定到某个 tag，例如 `spec-v0.1.0`。

## 用例覆盖范围

| 校验步骤 | 覆盖的场景 |
|---|---|
| 1 缺失 | token 为 null、为空字符串 |
| 2 格式 | 段数不对、非 base64url、头部不是 JSON、头部不是对象 |
| 3 typ | `JWT`（ID Token 冒充）、缺少 typ；`application/at+jwt` 和大写形式应当通过 |
| 4 alg | `none`、HS256 算法混淆攻击、RS512 |
| 5 kid | 缺失、刷新后仍未知、kty 与 alg 不匹配；轮换后的 kid 经刷新后应当通过 |
| 6 签名 | 攻击者密钥冒用 kid、篡改 payload |
| 7 claims | 11 个必填 claim 逐一缺失、类型错误、非法枚举值、负数、`aud` 为空数组、m2m token 无需 sid/asid |
| 8 iss | 尾部多斜杠、其他签发方 |
| 9–10 时间 | 容差内与容差外、恰好在边界上、nbf 和 iat 在未来 |
| 11 aud | 不匹配、数组中不包含、大小写不同；数组中包含时应当通过 |
| 12 吊销 | session、app_session、user（吊销前和吊销后签发）、client（匹配 azp 和匹配 aud）、无关事件不误伤、m2m token 不受 session 吊销影响 |
| 错误优先级 | token 同时过期且 aud 错误时，返回 `EXPIRED` |
