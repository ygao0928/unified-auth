# Unified Auth 契约规范（spec）

本目录是统一登录鉴权平台的**机器可读契约**。认证中心、三端 SDK（Go / Python / Java）以及前端 JS SDK 都必须以这里的定义为准。设计背景见 [`docs/design.md`](../docs/design.md)。

- 规范版本：`0.1.0`（草案，评审前可以有不兼容变更）
- 规范的关键字含义遵循 RFC 2119：必须（MUST）、不得（MUST NOT）、应当（SHOULD）、可以（MAY）。

## 目录

| 文件 | 内容 |
|---|---|
| [`openapi/auth-center.yaml`](openapi/auth-center.yaml) | 认证中心对外接口（OpenAPI 3.1）：OIDC 端点、吊销同步、权限查询、权限清单同步、会话管理 |
| [`schemas/access-token-claims.schema.json`](schemas/access-token-claims.schema.json) | Access Token（JWT）的 claims 定义 |
| [`schemas/user.schema.json`](schemas/user.schema.json) | SDK 对外暴露的 `User` 对象（三端字段一致） |
| [`schemas/error-response.schema.json`](schemas/error-response.schema.json) | 统一错误响应体 |
| [`error-codes.yaml`](error-codes.yaml) | 错误码清单：HTTP 状态码、触发条件、客户端处理方式 |
| [`schemas/revocation-event.schema.json`](schemas/revocation-event.schema.json) | 吊销事件 `auth.revoked` |
| [`schemas/authz-changed-event.schema.json`](schemas/authz-changed-event.schema.json) | 权限变更事件 `authz.changed` |
| [`schemas/authz-result.schema.json`](schemas/authz-result.schema.json) | 权限查询结果：权限点集合和数据范围 |
| [`schemas/permissions-manifest.schema.json`](schemas/permissions-manifest.schema.json) | 应用权限清单 `permissions.yaml` |
| [`schemas/audit-event.schema.json`](schemas/audit-event.schema.json) | 审计事件 |
| [`schemas/sdk-config.schema.json`](schemas/sdk-config.schema.json) | SDK 通用配置项 |
| [`token-validation.md`](token-validation.md) | **Access Token 校验算法**：SDK 必须严格按此顺序实现 |
| [`authorization.md`](authorization.md) | 权限点匹配规则和数据范围合并规则 |

## 与设计文档的对应关系

设计文档 [`docs/design.md`](../docs/design.md) 已按下列约定写回。实现以本目录和 [`conformance/`](../conformance/) 为准：

1. **新增必填 claim `asid`（应用会话 ID）**：设计中支持"只踢掉某一个应用会话"，SDK 需要依据 token 中的 `asid` 来匹配 `app_session` 类型的吊销事件。
2. **Access Token 的 JOSE 头 `typ` 必须为 `at+jwt`**（遵循 RFC 9068；也接受 `application/at+jwt`，不区分大小写）：用来防止 ID Token 被冒充成 Access Token 使用。SDK 必须拒绝其他 `typ`。
3. **允许的签名算法限定为 `RS256` 和 `ES256`**：SDK 必须使用白名单校验算法，不得根据 token 头部声明的 `alg` 动态选择验证方式。
4. **`aud` 可以是字符串或数组**：token exchange 场景下可能有多个受众。SDK 只要求自己的 `client_id` 包含在其中即可。
5. **User 对象中的 `client_id` 取自 `azp`**：表示实际发起请求的客户端。

## 兼容性规则

- 新增**可选**字段属于兼容变更，只升级次版本号。SDK 必须忽略不认识的 claims 和事件字段。
- 新增必填字段、删除字段、改变字段语义，属于不兼容变更，需要升级主版本号。
- 错误码**只增不改**：已发布的错误码不得改名，也不得改变含义。
