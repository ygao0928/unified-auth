import { Button, Space, Table, Tag, Typography, message } from "antd";
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { ApiError, errorText, type AdminApi } from "../api";
import type { AppRecord } from "../types";

export function AppListPage({ api, onUnauthorized }: { api: AdminApi; onUnauthorized: () => void }) {
  const navigate = useNavigate();
  const [apps, setApps] = useState<AppRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .listApps()
      .then((rows) => {
        if (!cancelled) {
          setApps(rows);
        }
      })
      .catch((err: unknown) => {
        if (err instanceof ApiError && err.status === 401) {
          onUnauthorized();
          return;
        }
        message.error(errorText(err));
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [api, onUnauthorized]);

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Typography.Title level={3} style={{ margin: 0 }}>
          应用
        </Typography.Title>
        <Button type="primary" onClick={() => navigate("/apps/new")}>
          注册应用
        </Button>
      </Space>
      <Table<AppRecord>
        rowKey="client_id"
        loading={loading}
        dataSource={apps}
        pagination={false}
        locale={{ emptyText: "还没有应用" }}
        columns={[
          {
            title: "client_id",
            dataIndex: "client_id",
            render: (id: string) => <Link to={`/apps/${encodeURIComponent(id)}`}>{id}</Link>,
          },
          { title: "名称", dataIndex: "name" },
          { title: "类型", dataIndex: "client_type" },
          {
            title: "密钥",
            dataIndex: "public",
            render: (isPublic: boolean) => (isPublic ? <Tag>公开</Tag> : <Tag color="blue">机密</Tag>),
          },
          {
            title: "状态",
            dataIndex: "enabled",
            render: (enabled: boolean) => (enabled ? <Tag color="green">启用</Tag> : <Tag>停用</Tag>),
          },
          {
            title: "",
            key: "actions",
            render: (_, row) => <Link to={`/apps/${encodeURIComponent(row.client_id)}`}>查看</Link>,
          },
        ]}
      />
    </Space>
  );
}
