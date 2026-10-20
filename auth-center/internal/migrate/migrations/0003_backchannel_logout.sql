-- OIDC back-channel logout 的通知地址。设计 ER 图没有这一列。
-- 为空时登出仍结束会话并发布 auth.revoked，只是不发 HTTP 通知。

ALTER TABLE clients ADD COLUMN backchannel_logout_uri TEXT;

ALTER TABLE clients ADD CONSTRAINT clients_backchannel_logout_uri_chk
    CHECK (backchannel_logout_uri IS NULL OR length(backchannel_logout_uri) > 0);
