import { Alert, Button, Modal, Typography } from "antd";

export function SecretDialog({ secret, onClose }: { secret: string; onClose: () => void }) {
  if (!secret) {
    return null;
  }
  return (
    <Modal
      open
      destroyOnHidden
      title="客户端密钥"
      onCancel={onClose}
      footer={
        <Button type="primary" onClick={onClose}>
          我已保存
        </Button>
      }
    >
      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 16 }}
        message="密钥只显示这一次。关闭后无法再查看，只能轮换生成新密钥。"
      />
      <Typography.Paragraph copyable={{ text: secret }} style={{ marginBottom: 0 }}>
        <Typography.Text code>{secret}</Typography.Text>
      </Typography.Paragraph>
    </Modal>
  );
}
