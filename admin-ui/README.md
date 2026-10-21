# 管理后台

应用注册页面。技术栈是 React、TypeScript、Vite，组件库是 Ant Design。

页面调用认证中心已有的 `/api/v1/apps`：

- 列出、查看、注册、编辑应用
- 配置回调地址、back-channel logout URI、客户端类型和是否公开
- 按应用覆盖 token 与会话有效期；留空等于设计 §5.2 的全局默认
- 轮换密钥，明文只在弹窗里显示一次

开发时 Vite 把 `/api` 代理到认证中心，浏览器与 API 同源，不另加 CORS。先启动认证中心并设置 `AUTH_CENTER_ADMIN_TOKEN`，再：

```bash
cd admin-ui
npm ci
npm run dev
```

打开 http://127.0.0.1:5173 ，填入同一个引导令牌。令牌只放在 `sessionStorage`。

多身份源选择页不在这里。多个身份源且没有 `idp_hint` 时，认证中心的 `/oauth2/authorize` 返回服务端渲染的选择页。

```bash
npm test
npm run lint
npm run build
```
