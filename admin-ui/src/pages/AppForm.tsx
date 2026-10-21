import { Button, Form, Input, InputNumber, Select, Space, Switch, Typography } from "antd";
import { useEffect } from "react";

import { canBePublic, defaultHint, validateAppForm } from "../form";
import { clientTypes, emptyForm, type AppFormValues, type ClientType } from "../types";

const labels: Record<ClientType, string> = {
  web: "web",
  ssr: "ssr",
  app: "app",
  miniapp: "miniapp",
  m2m: "m2m",
};

export function AppForm({
  mode,
  initial,
  submitting,
  onSubmit,
  onCancel,
}: {
  mode: "create" | "edit";
  initial?: AppFormValues;
  submitting: boolean;
  onSubmit: (values: AppFormValues) => void;
  onCancel: () => void;
}) {
  const [form] = Form.useForm<AppFormValues>();
  const clientType = Form.useWatch("clientType", form) ?? initial?.clientType ?? "web";

  useEffect(() => {
    form.setFieldsValue(initial ?? emptyForm());
  }, [form, initial]);

  return (
    <Form<AppFormValues>
      form={form}
      layout="vertical"
      initialValues={initial ?? emptyForm()}
      onFinish={(values) => {
        const errors = validateAppForm(values, mode);
        if (Object.keys(errors).length > 0) {
          form.setFields(
            Object.entries(errors).map(([name, message]) => ({
              name: name as keyof AppFormValues,
              errors: [message],
            })),
          );
          return;
        }
        onSubmit(values);
      }}
    >
      {mode === "create" ? (
        <Form.Item label="client_id" name="clientId" extra="留空则由认证中心生成">
          <Input placeholder="meeting" autoComplete="off" />
        </Form.Item>
      ) : null}
      <Form.Item label="名称" name="name" rules={[{ required: true, message: "请填写名称" }]}>
        <Input />
      </Form.Item>
      <Form.Item label="客户端类型" name="clientType">
        <Select
          options={clientTypes.map((value) => ({ value, label: labels[value] }))}
          onChange={(value: ClientType) => {
            if (!canBePublic(value)) {
              form.setFieldValue("publicClient", false);
            }
            if (value === "m2m") {
              form.setFieldValue("refreshTokenTtl", null);
              form.setFieldValue("idleTimeout", null);
              form.setFieldValue("absoluteSessionTtl", null);
            }
          }}
        />
      </Form.Item>
      <Form.Item
        label="公开客户端"
        name="publicClient"
        valuePropName="checked"
        extra="公开客户端不生成密钥。只有 web、app、miniapp 可以公开。"
      >
        <Switch disabled={!canBePublic(clientType)} />
      </Form.Item>
      <Form.Item label="回调地址" name="redirectText" extra="每行一个绝对地址，授权和登出回跳都按这个列表精确匹配">
        <Input.TextArea rows={4} placeholder="https://meeting.example.com/auth/callback" />
      </Form.Item>
      <Form.Item label="back-channel logout URI" name="backchannelLogoutUri" extra="可空。有值时，全局登出会向这个地址 POST logout_token">
        <Input placeholder="https://meeting.example.com/backchannel-logout" />
      </Form.Item>
      <Typography.Paragraph type="secondary">{defaultHint(clientType)}</Typography.Paragraph>
      <Form.Item label="access_token_ttl（秒）" name="accessTokenTtl">
        <InputNumber min={1} precision={0} style={{ width: "100%" }} placeholder="留空使用全局默认" />
      </Form.Item>
      {clientType === "m2m" ? null : (
        <>
          <Form.Item label="refresh_token_ttl（秒）" name="refreshTokenTtl">
            <InputNumber min={1} precision={0} style={{ width: "100%" }} placeholder="留空使用全局默认" />
          </Form.Item>
          <Form.Item label="idle_timeout（秒）" name="idleTimeout">
            <InputNumber min={1} precision={0} style={{ width: "100%" }} placeholder="留空使用全局默认" />
          </Form.Item>
          <Form.Item label="absolute_session_ttl（秒）" name="absoluteSessionTtl">
            <InputNumber min={1} precision={0} style={{ width: "100%" }} placeholder="留空使用全局默认" />
          </Form.Item>
        </>
      )}
      {mode === "edit" ? (
        <Form.Item label="启用" name="enabled" valuePropName="checked">
          <Switch />
        </Form.Item>
      ) : null}
      <Space>
        <Button type="primary" htmlType="submit" loading={submitting}>
          {mode === "create" ? "注册" : "保存"}
        </Button>
        <Button onClick={onCancel}>取消</Button>
      </Space>
    </Form>
  );
}
