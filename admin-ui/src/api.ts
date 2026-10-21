import type { AppCreate, AppPatch, AppRecord } from "./types";

export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export class AdminApi {
  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
  ) {}

  listApps(): Promise<AppRecord[]> {
    return this.request<{ apps: AppRecord[] }>("GET", "/api/v1/apps").then((body) => body.apps ?? []);
  }

  getApp(clientId: string): Promise<AppRecord> {
    return this.request<AppRecord>("GET", `/api/v1/apps/${encodeURIComponent(clientId)}`);
  }

  createApp(body: AppCreate): Promise<AppRecord> {
    return this.request<AppRecord>("POST", "/api/v1/apps", body);
  }

  updateApp(clientId: string, body: AppPatch): Promise<AppRecord> {
    return this.request<AppRecord>("PATCH", `/api/v1/apps/${encodeURIComponent(clientId)}`, body);
  }

  rotateSecret(clientId: string): Promise<AppRecord> {
    return this.request<AppRecord>("POST", `/api/v1/apps/${encodeURIComponent(clientId)}/secret`);
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { Authorization: `Bearer ${this.token}` };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    const response = await fetch(joinUrl(this.baseUrl, path), {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    const payload = text ? (JSON.parse(text) as Record<string, unknown>) : {};
    if (!response.ok) {
      const code = typeof payload.code === "string" ? payload.code : "INVALID_REQUEST";
      const message = typeof payload.message === "string" ? payload.message : "request failed";
      throw new ApiError(response.status, code, message);
    }
    return payload as T;
  }
}

export function joinUrl(base: string, path: string): string {
  const trimmed = base.replace(/\/$/, "");
  return `${trimmed}${path}`;
}

export function errorText(err: unknown): string {
  if (err instanceof ApiError) {
    return err.message;
  }
  return "请求失败";
}
