import { AdminApi, ApiError } from "./api";
import type { AppRecord } from "./types";

const app: AppRecord = {
  client_id: "meeting",
  name: "会议",
  client_type: "web",
  redirect_uris: ["https://meeting.example/cb"],
  enabled: true,
  public: false,
  session_policy: { access_token_ttl: 90 },
};

function mockFetch(status: number, body: unknown) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("AdminApi", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("lists apps with the bearer token and does not expect a secret", async () => {
    const fetchMock = mockFetch(200, { apps: [app] });
    const api = new AdminApi("http://auth.example", "bootstrap");
    await expect(api.listApps()).resolves.toEqual([app]);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://auth.example/api/v1/apps");
    expect(init.headers).toMatchObject({ Authorization: "Bearer bootstrap" });
    expect(init.body).toBeUndefined();
  });

  it("creates an app and returns the one-time secret", async () => {
    const fetchMock = mockFetch(201, { ...app, client_secret: "shown-once" });
    const api = new AdminApi("", "bootstrap");
    const created = await api.createApp({ name: "会议", client_type: "web", redirect_uris: ["https://meeting.example/cb"] });
    expect(created.client_secret).toBe("shown-once");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/apps");
    expect(init.method).toBe("POST");
  });

  it("patches and rotates without sending the old secret", async () => {
    const fetchMock = mockFetch(200, { ...app, client_secret: "rotated" });
    const api = new AdminApi("http://auth.example/", "bootstrap");
    await api.updateApp("meeting", { name: "新名称", enabled: false, session_policy: {} });
    await api.rotateSecret("meeting");
    const patch = fetchMock.mock.calls[0] as [string, RequestInit];
    const rotate = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(patch[0]).toBe("http://auth.example/api/v1/apps/meeting");
    expect(patch[1].method).toBe("PATCH");
    expect(String(patch[1].body)).not.toContain("client_secret");
    expect(rotate[0]).toBe("http://auth.example/api/v1/apps/meeting/secret");
    expect(rotate[1].method).toBe("POST");
    expect(rotate[1].body).toBeUndefined();
  });

  it("surfaces the API error message", async () => {
    mockFetch(401, { code: "AUTH_TOKEN_INVALID", message: "admin credential is invalid" });
    const api = new AdminApi("", "nope");
    await expect(api.getApp("meeting")).rejects.toMatchObject({
      status: 401,
      code: "AUTH_TOKEN_INVALID",
      message: "admin credential is invalid",
    } satisfies Partial<ApiError>);
  });
});
