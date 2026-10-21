import { Button, Layout } from "antd";
import { useCallback, useMemo, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";

import { AdminApi } from "./api";
import { AppDetailPage } from "./pages/AppDetailPage";
import { AppEditPage } from "./pages/AppEditPage";
import { AppListPage } from "./pages/AppListPage";
import { ConnectPage } from "./pages/ConnectPage";
import { clearToken, loadToken, saveToken } from "./session";

const { Header, Content } = Layout;

export function AdminApp() {
  const [token, setToken] = useState(loadToken);
  const api = useMemo(() => new AdminApi(import.meta.env.VITE_API_BASE ?? "", token), [token]);
  const onUnauthorized = useCallback(() => {
    clearToken();
    setToken("");
  }, []);

  if (!token) {
    return (
      <ConnectPage
        onConnect={(next) => {
          saveToken(next);
          setToken(next);
        }}
      />
    );
  }

  return (
    <Layout style={{ minHeight: "100vh" }}>
      <Header style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <span style={{ color: "#fff", fontSize: 16 }}>统一认证 · 应用注册</span>
        <Button onClick={onUnauthorized}>退出</Button>
      </Header>
      <Content style={{ padding: 24, maxWidth: 960, width: "100%", margin: "0 auto" }}>
        <Routes>
          <Route path="/" element={<Navigate to="/apps" replace />} />
          <Route path="/apps" element={<AppListPage api={api} onUnauthorized={onUnauthorized} />} />
          <Route path="/apps/new" element={<AppEditPage api={api} mode="create" onUnauthorized={onUnauthorized} />} />
          <Route path="/apps/:clientId" element={<AppDetailPage api={api} onUnauthorized={onUnauthorized} />} />
          <Route path="/apps/:clientId/edit" element={<AppEditPage api={api} mode="edit" onUnauthorized={onUnauthorized} />} />
        </Routes>
      </Content>
    </Layout>
  );
}
