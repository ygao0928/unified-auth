-- 只读基础角色。权限点仍属于 P5，这里不建 permission 表。
-- default:viewer 只在用户第一次插入时授予，已有用户不补授。

CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    name TEXT NOT NULL,
    data_scope TEXT,
    CONSTRAINT roles_id_chk CHECK (length(id) > 0),
    CONSTRAINT roles_name_chk CHECK (length(name) > 0),
    CONSTRAINT roles_scope_chk CHECK (scope = 'global' OR (left(scope, 4) = 'app:' AND length(scope) > 4)),
    CONSTRAINT roles_data_scope_chk CHECK (data_scope IS NULL OR data_scope IN ('self', 'dept', 'dept_and_sub', 'all'))
);

CREATE TABLE user_roles (
    emp_no TEXT NOT NULL REFERENCES users (emp_no),
    role_id TEXT NOT NULL REFERENCES roles (id),
    grant_source TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (emp_no, role_id),
    CONSTRAINT user_roles_grant_source_chk CHECK (grant_source IN ('manual', 'default', 'approval'))
);

INSERT INTO roles (id, scope, name, data_scope)
VALUES ('default:viewer', 'global', 'viewer', 'self');
