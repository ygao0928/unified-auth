import { Card, Typography, message } from "antd";
import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { ApiError, errorText, type AdminApi } from "../api";
import { buildCreate, buildPatch } from "../form";
import { formFromApp, type AppFormValues } from "../types";
import { AppForm } from "./AppForm";

export function AppEditPage({
  api,
  mode,
  onUnauthorized,
}: {
  api: AdminApi;
  mode: "create" | "edit";
  onUnauthorized: () => void;
}) {
  const navigate = useNavigate();
  const { clientId = "" } = useParams();
  const [initial, setInitial] = useState<AppFormValues | undefined>();
  const [ready, setReady] = useState(mode === "create");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (mode !== "edit") {
      return;
    }
    let cancelled = false;
    api
      .getApp(clientId)
      .then((app) => {
        if (!cancelled) {
          setInitial(formFromApp(app));
          setReady(true);
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
  }, [api, clientId, mode, onUnauthorized]);

  async function submit(values: AppFormValues) {
    setSubmitting(true);
    try {
      if (mode === "create") {
        const created = await api.createApp(buildCreate(values));
        navigate(`/apps/${encodeURIComponent(created.client_id)}`, {
          state: { secret: created.client_secret ?? "" },
        });
        return;
      }
      const updated = await api.updateApp(clientId, buildPatch(values));
      message.success("已保存");
      navigate(`/apps/${encodeURIComponent(updated.client_id)}`);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized();
        return;
      }
      message.error(errorText(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card title={mode === "create" ? "注册应用" : "编辑应用"}>
      {ready && (mode === "create" || initial) ? (
        <AppForm
          mode={mode}
          initial={initial}
          submitting={submitting}
          onSubmit={(values) => void submit(values)}
          onCancel={() => navigate(mode === "create" ? "/apps" : `/apps/${encodeURIComponent(clientId)}`)}
        />
      ) : (
        <Typography.Paragraph>正在读取应用…</Typography.Paragraph>
      )}
    </Card>
  );
}
