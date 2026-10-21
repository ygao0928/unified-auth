import { Button, Card, Descriptions, Space, Tag, Typography, message } from "antd";
import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";

import { ApiError, errorText, type AdminApi } from "../api";
import type { AppRecord } from "../types";
import { SecretDialog } from "./SecretDialog";

function ttl(value: number | undefined): string {
  return value == null ? "全局默认" : `${value} 秒`;
}

export function AppDetailPage({ api, onUnauthorized }: { api: AdminApi; onUnauthorized: () => void }) {
  const { clientId = "" } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const arrived = (location.state as { secret?: string } | null)?.secret ?? "";
  const [app, setApp] = useState<AppRecord | null>(null);
  const [secret, setSecret] = useState(arrived);
  const [rotating, setRotating] = useState(false);

  useEffect(() => {
    if (arrived) {
      navigate(location.pathname, { replace: true, state: null });
    }
  }, [arrived, location.pathname, navigate]);

  useEffect(() => {
    let cancelled = false;
    api
      .getApp(clientId)
      .then((row) => {
        if (!cancelled) {
          setApp(row);
        }
      })
      .catch((err: unknown) => {
        if (err instanceof ApiError && err.status === 401) {
          onUnauthorized();
          return;
        }
        message.error(errorText(err));
      });
    return () => {
      cancelled = true;
    };
  }, [api, clientId, onUnauthorized]);

  async function rotate() {
    setRotating(true);
    try {
      const updated = await api.rotateSecret(clientId);
      setApp(updated);
      setSecret(updated.client_secret ?? "");
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized();
        return;
      }
      message.error(errorText(err));
    } finally {
      setRotating(false);
    }
  }

  if (!app) {
    return <Typography.Paragraph>正在读取应用…</Typography.Paragraph>;
  }

  const policy = app.session_policy ?? {};
  return (
    <Card
      title={app.name}
      extra={
        <Space>
          <Link to="/apps">返回列表</Link>
          <Button onClick={() => navigate(`/apps/${encodeURIComponent(app.client_id)}/edit`)}>编辑</Button>
          <Button type="primary" loading={rotating} onClick={() => void rotate()}>
            轮换密钥
          </Button>
        </Space>
      }
    >
      <Descriptions column={1} bordered>
        <Descriptions.Item label="client_id">{app.client_id}</Descriptions.Item>
        <Descriptions.Item label="类型">{app.client_type}</Descriptions.Item>
        <Descriptions.Item label="密钥">{app.public ? <Tag>公开</Tag> : <Tag color="blue">机密</Tag>}</Descriptions.Item>
        <Descriptions.Item label="状态">{app.enabled ? <Tag color="green">启用</Tag> : <Tag>停用</Tag>}</Descriptions.Item>
        <Descriptions.Item label="回调地址">
          {(app.redirect_uris ?? []).length === 0 ? "无" : app.redirect_uris.map((uri) => <div key={uri}>{uri}</div>)}
        </Descriptions.Item>
        <Descriptions.Item label="back-channel logout URI">{app.backchannel_logout_uri || "无"}</Descriptions.Item>
        <Descriptions.Item label="access_token_ttl">{ttl(policy.access_token_ttl)}</Descriptions.Item>
        {app.client_type === "m2m" ? null : (
          <Descriptions.Item label="refresh_token_ttl">{ttl(policy.refresh_token_ttl)}</Descriptions.Item>
        )}
        {app.client_type === "m2m" ? null : (
          <Descriptions.Item label="idle_timeout">{ttl(policy.idle_timeout)}</Descriptions.Item>
        )}
        {app.client_type === "m2m" ? null : (
          <Descriptions.Item label="absolute_session_ttl">{ttl(policy.absolute_session_ttl)}</Descriptions.Item>
        )}
      </Descriptions>
      <SecretDialog secret={secret} onClose={() => setSecret("")} />
    </Card>
  );
}
