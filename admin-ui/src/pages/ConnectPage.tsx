import { Button, Card, Form, Input, Typography } from "antd";

export function ConnectPage({ onConnect }: { onConnect: (token: string) => void }) {
  return (
    <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", background: "#f5f5f5" }}>
      <Card title="连接认证中心" style={{ width: 440 }}>
        <Typography.Paragraph type="secondary">
          填写环境变量 AUTH_CENTER_ADMIN_TOKEN。令牌只留在这个浏览器会话里，页面通过同源的 /api 调用应用注册接口。
        </Typography.Paragraph>
        <Form<{ token: string }>
          layout="vertical"
          onFinish={(values) => {
            const token = values.token.trim();
            if (token) {
              onConnect(token);
            }
          }}
        >
          <Form.Item label="引导令牌" name="token" rules={[{ required: true, message: "请填写引导令牌" }]}>
            <Input.Password autoComplete="off" />
          </Form.Item>
          <Button type="primary" htmlType="submit" block>
            进入
          </Button>
        </Form>
      </Card>
    </div>
  );
}
