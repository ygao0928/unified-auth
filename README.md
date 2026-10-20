# Unified Auth

公司级统一登录鉴权平台：对接公司 SSO（CAS / SAML / OIDC），为 Go、FastAPI、SpringBoot 项目，以及 Web、移动 App、小程序、第三方 Open API 提供统一的认证、会话与权限能力。

## 文档

- [设计文档 v0.1（待评审）](docs/design.md)
- [开发任务分解](docs/tasks.md)：按 P0–P7 拆分的任务、依赖和关键路径
- [认证中心](auth-center/README.md)：P1 的 Go 服务（Chi、PostgreSQL、Redis、OIDC 授权码）
- [契约规范 spec/](spec/README.md)：OpenAPI、claims、错误码、事件、token 校验算法、权限规则
- [一致性测试 conformance/](conformance/README.md)：三端 SDK 必须通过的测试向量

## 核心思路

- **协议在中心收敛**：Auth Center（Go 实现）对接上游三种 SSO 协议，对下游统一以 OIDC / JWT 输出。
- **本地验签**：各项目通过薄 SDK 在本地完成验签和权限校验；业务请求不依赖认证中心实时在线。
- **契约优先**：claims、错误码、事件格式统一定义；三端 SDK 必须通过同一套一致性测试。
- **集中定义，分布执行**：权限在中心集中管理，由各项目在本地执行校验；支持跨应用的通用角色。
