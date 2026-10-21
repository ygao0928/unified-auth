import type { AppCreate, AppFormValues, AppPatch, ClientType, SessionPolicy } from "./types";

const publicTypes = new Set<ClientType>(["web", "app", "miniapp"]);
const clientIdPattern = /^[A-Za-z0-9._-]{1,128}$/;

export function parseRedirects(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const uri = line.trim();
    if (!uri || seen.has(uri)) {
      continue;
    }
    seen.add(uri);
    out.push(uri);
  }
  return out;
}

export function isAbsoluteHttp(raw: string): boolean {
  try {
    const url = new URL(raw);
    return (url.protocol === "http:" || url.protocol === "https:") && url.host !== "";
  } catch {
    return false;
  }
}

export function canBePublic(clientType: ClientType): boolean {
  return publicTypes.has(clientType);
}

function ttl(value: number | null): number | undefined {
  if (value == null || Number.isNaN(value)) {
    return undefined;
  }
  return value;
}

export function sessionPolicy(values: AppFormValues): SessionPolicy {
  const policy: SessionPolicy = {};
  const access = ttl(values.accessTokenTtl);
  if (access != null) {
    policy.access_token_ttl = access;
  }
  if (values.clientType === "m2m") {
    return policy;
  }
  const refresh = ttl(values.refreshTokenTtl);
  const idle = ttl(values.idleTimeout);
  const absolute = ttl(values.absoluteSessionTtl);
  if (refresh != null) {
    policy.refresh_token_ttl = refresh;
  }
  if (idle != null) {
    policy.idle_timeout = idle;
  }
  if (absolute != null) {
    policy.absolute_session_ttl = absolute;
  }
  return policy;
}

export function defaultHint(clientType: ClientType): string {
  if (clientType === "m2m") {
    return "留空则 access token 使用全局默认 1800 秒。m2m 不签发 refresh token，也没有空闲超时和绝对时长。";
  }
  if (clientType === "app" || clientType === "miniapp") {
    return "留空则使用全局默认：access 600 秒，refresh 600 秒，空闲 604800 秒，绝对 2592000 秒。";
  }
  return "留空则使用全局默认：access 600 秒，refresh 600 秒，空闲 7200 秒，绝对 43200 秒。ssr 与 web 相同。";
}

export function validateAppForm(values: AppFormValues, mode: "create" | "edit"): Record<string, string> {
  const errors: Record<string, string> = {};
  if (!values.name.trim()) {
    errors.name = "请填写名称";
  }
  if (mode === "create" && values.clientId.trim() && !clientIdPattern.test(values.clientId.trim())) {
    errors.clientId = "client_id 只能包含字母、数字、点、下划线和连字符";
  }
  if (values.publicClient && !canBePublic(values.clientType)) {
    errors.publicClient = "只有 web、app、miniapp 可以不配置密钥";
  }
  const redirects = parseRedirects(values.redirectText);
  if (values.clientType !== "m2m" && redirects.length === 0) {
    errors.redirectText = "除 m2m 外至少要有一个回调地址";
  }
  if (redirects.some((uri) => !isAbsoluteHttp(uri))) {
    errors.redirectText = "回调地址必须是绝对的 http 或 https 地址";
  }
  const back = values.backchannelLogoutUri.trim();
  if (back && !isAbsoluteHttp(back)) {
    errors.backchannelLogoutUri = "back-channel 地址必须是绝对的 http 或 https 地址";
  }
  for (const [key, value] of [
    ["accessTokenTtl", values.accessTokenTtl],
    ["refreshTokenTtl", values.refreshTokenTtl],
    ["idleTimeout", values.idleTimeout],
    ["absoluteSessionTtl", values.absoluteSessionTtl],
  ] as const) {
    if (value != null && (!Number.isInteger(value) || value < 1)) {
      errors[key] = "有效期必须是大于等于 1 的整数秒";
    }
  }
  if (values.clientType === "m2m" && (values.refreshTokenTtl != null || values.idleTimeout != null || values.absoluteSessionTtl != null)) {
    errors.refreshTokenTtl = "m2m 不能覆盖 refresh、空闲或绝对时长";
  }
  return errors;
}

export function buildCreate(values: AppFormValues): AppCreate {
  const body: AppCreate = {
    name: values.name.trim(),
    client_type: values.clientType,
    redirect_uris: parseRedirects(values.redirectText),
    public: values.publicClient,
  };
  const clientId = values.clientId.trim();
  if (clientId) {
    body.client_id = clientId;
  }
  const back = values.backchannelLogoutUri.trim();
  if (back) {
    body.backchannel_logout_uri = back;
  }
  const policy = sessionPolicy(values);
  if (Object.keys(policy).length > 0) {
    body.session_policy = policy;
  }
  return body;
}

export function buildPatch(values: AppFormValues): AppPatch {
  return {
    name: values.name.trim(),
    client_type: values.clientType,
    redirect_uris: parseRedirects(values.redirectText),
    backchannel_logout_uri: values.backchannelLogoutUri.trim(),
    session_policy: sessionPolicy(values),
    enabled: values.enabled,
  };
}
