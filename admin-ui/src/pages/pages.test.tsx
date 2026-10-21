import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import { AdminApi } from "../api";
import type { AppRecord } from "../types";
import { AppDetailPage } from "./AppDetailPage";
import { AppEditPage } from "./AppEditPage";
import { AppListPage } from "./AppListPage";
import { SecretDialog } from "./SecretDialog";

const app: AppRecord = {
  client_id: "meeting",
  name: "会议",
  client_type: "web",
  redirect_uris: ["https://meeting.example/cb"],
  backchannel_logout_uri: "https://meeting.example/logout",
  session_policy: { access_token_ttl: 90 },
  enabled: true,
  public: false,
};

function listApi(): AdminApi {
  return {
    listApps: vi.fn().mockResolvedValue([app]),
  } as unknown as AdminApi;
}

describe("admin pages", () => {
  it("lists applications and links to the detail page", async () => {
    render(
      <MemoryRouter>
        <AppListPage api={listApi()} onUnauthorized={() => undefined} />
      </MemoryRouter>,
    );
    expect(await screen.findByText("会议")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "meeting" })).toHaveAttribute("href", "/apps/meeting");
    expect(screen.getByText("机密")).toBeInTheDocument();
  });

  it("shows a secret once and removes it after the operator confirms", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const view = render(<SecretDialog secret="shown-once" onClose={onClose} />);
    expect(screen.getByText("shown-once")).toBeInTheDocument();
    expect(screen.getByText(/只显示这一次/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "我已保存" }));
    expect(onClose).toHaveBeenCalledOnce();
    view.rerender(<SecretDialog secret="" onClose={onClose} />);
    expect(screen.queryByText("shown-once")).not.toBeInTheDocument();
  });

  it("does not call the API when a web app has no redirect", async () => {
    const user = userEvent.setup();
    const createApp = vi.fn();
    const api = { createApp } as unknown as AdminApi;
    render(
      <MemoryRouter initialEntries={["/apps/new"]}>
        <Routes>
          <Route path="/apps/new" element={<AppEditPage api={api} mode="create" onUnauthorized={() => undefined} />} />
        </Routes>
      </MemoryRouter>,
    );
    await user.type(screen.getByLabelText("名称"), "会议");
    await user.click(screen.getByRole("button", { name: "注 册" }));
    expect(await screen.findByText("除 m2m 外至少要有一个回调地址")).toBeInTheDocument();
    expect(createApp).not.toHaveBeenCalled();
  });

  it("rotates a secret and shows the new value once", async () => {
    const user = userEvent.setup();
    const api = {
      getApp: vi.fn().mockResolvedValue(app),
      rotateSecret: vi.fn().mockResolvedValue({ ...app, public: false, client_secret: "rotated-secret" }),
    } as unknown as AdminApi;
    render(
      <MemoryRouter initialEntries={["/apps/meeting"]}>
        <Routes>
          <Route path="/apps/:clientId" element={<AppDetailPage api={api} onUnauthorized={() => undefined} />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(await screen.findByText("https://meeting.example/cb")).toBeInTheDocument();
    expect(screen.getByText("90 秒")).toBeInTheDocument();
    expect(screen.getByText("https://meeting.example/logout")).toBeInTheDocument();
    expect(screen.queryByText("client_secret")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "轮换密钥" }));
    expect(await screen.findByText("rotated-secret")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "我已保存" }));
    expect(screen.queryByText("rotated-secret")).not.toBeInTheDocument();
  });
});
