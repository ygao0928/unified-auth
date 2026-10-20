-- 客户端注册、用户和上游身份源。权限表属于 P5。
-- secret_hash 只存哈希，算法尚未决定。明文 secret 不入库。

CREATE TABLE clients (
    client_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    client_type TEXT NOT NULL,
    secret_hash TEXT,
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    session_policy JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT clients_client_id_chk CHECK (length(client_id) > 0),
    CONSTRAINT clients_name_chk CHECK (length(name) > 0),
    CONSTRAINT clients_client_type_chk CHECK (client_type IN ('web', 'ssr', 'app', 'miniapp', 'm2m'))
);

CREATE TABLE users (
    emp_no TEXT PRIMARY KEY,
    name TEXT,
    email TEXT,
    mobile TEXT,
    dept_id TEXT,
    dept_name TEXT,
    perm_ver INTEGER NOT NULL DEFAULT 0,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_emp_no_chk CHECK (length(emp_no) > 0),
    CONSTRAINT users_perm_ver_chk CHECK (perm_ver >= 0)
);

CREATE TABLE identity_providers (
    id TEXT PRIMARY KEY,
    protocol TEXT NOT NULL,
    display_name TEXT NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    attribute_mapping JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT identity_providers_id_chk CHECK (length(id) > 0),
    CONSTRAINT identity_providers_protocol_chk CHECK (protocol IN ('CAS', 'SAML', 'OIDC', 'CUSTOM'))
);
