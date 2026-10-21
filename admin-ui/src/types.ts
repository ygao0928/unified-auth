export const clientTypes = ["web", "ssr", "app", "miniapp", "m2m"] as const;

export type ClientType = (typeof clientTypes)[number];

export type SessionPolicy = {
  access_token_ttl?: number;
  refresh_token_ttl?: number;
  idle_timeout?: number;
  absolute_session_ttl?: number;
};

export type AppRecord = {
  client_id: string;
  name: string;
  client_type: ClientType;
  redirect_uris: string[];
  backchannel_logout_uri?: string;
  session_policy?: SessionPolicy;
  enabled: boolean;
  public: boolean;
  client_secret?: string;
};

export type AppCreate = {
  client_id?: string;
  name: string;
  client_type: ClientType;
  redirect_uris?: string[];
  backchannel_logout_uri?: string;
  session_policy?: SessionPolicy;
  public?: boolean;
};

export type AppPatch = {
  name?: string;
  client_type?: ClientType;
  redirect_uris?: string[];
  backchannel_logout_uri?: string;
  session_policy?: SessionPolicy;
  enabled?: boolean;
};

export type AppFormValues = {
  clientId: string;
  name: string;
  clientType: ClientType;
  publicClient: boolean;
  redirectText: string;
  backchannelLogoutUri: string;
  accessTokenTtl: number | null;
  refreshTokenTtl: number | null;
  idleTimeout: number | null;
  absoluteSessionTtl: number | null;
  enabled: boolean;
};

export function emptyForm(): AppFormValues {
  return {
    clientId: "",
    name: "",
    clientType: "web",
    publicClient: false,
    redirectText: "",
    backchannelLogoutUri: "",
    accessTokenTtl: null,
    refreshTokenTtl: null,
    idleTimeout: null,
    absoluteSessionTtl: null,
    enabled: true,
  };
}

export function formFromApp(app: AppRecord): AppFormValues {
  return {
    clientId: app.client_id,
    name: app.name,
    clientType: app.client_type,
    publicClient: app.public,
    redirectText: (app.redirect_uris ?? []).join("\n"),
    backchannelLogoutUri: app.backchannel_logout_uri ?? "",
    accessTokenTtl: app.session_policy?.access_token_ttl ?? null,
    refreshTokenTtl: app.session_policy?.refresh_token_ttl ?? null,
    idleTimeout: app.session_policy?.idle_timeout ?? null,
    absoluteSessionTtl: app.session_policy?.absolute_session_ttl ?? null,
    enabled: app.enabled,
  };
}
