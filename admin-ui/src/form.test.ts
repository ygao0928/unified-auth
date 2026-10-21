import { buildCreate, buildPatch, parseRedirects, validateAppForm } from "./form";
import { emptyForm, type AppFormValues } from "./types";

function values(partial: Partial<AppFormValues> = {}): AppFormValues {
  return { ...emptyForm(), name: "会议", redirectText: "https://meeting.example/cb", ...partial };
}

describe("app form", () => {
  it("omits empty lifetimes and treats a blank client id as generated", () => {
    const body = buildCreate(values());
    expect(body.client_id).toBeUndefined();
    expect(body.session_policy).toBeUndefined();
    expect(body.redirect_uris).toEqual(["https://meeting.example/cb"]);
    expect(body.public).toBe(false);
  });

  it("keeps a token ttl override and drops the other lifetimes", () => {
    const body = buildCreate(values({ accessTokenTtl: 90, publicClient: true }));
    expect(body.public).toBe(true);
    expect(body.session_policy).toEqual({ access_token_ttl: 90 });
  });

  it("sends an empty policy when an edit clears every override", () => {
    const body = buildPatch(values({ backchannelLogoutUri: "" }));
    expect(body.session_policy).toEqual({});
    expect(body.backchannel_logout_uri).toBe("");
    expect(body.enabled).toBe(true);
  });

  it("rejects a public ssr client and a web client without a redirect", () => {
    expect(validateAppForm(values({ clientType: "ssr", publicClient: true }), "create").publicClient).toBeTruthy();
    expect(validateAppForm(values({ redirectText: "" }), "create").redirectText).toBeTruthy();
  });

  it("allows an m2m client with no redirect", () => {
    const errors = validateAppForm(values({ clientType: "m2m", redirectText: "", accessTokenTtl: 120 }), "create");
    expect(errors).toEqual({});
    expect(buildCreate(values({ clientType: "m2m", redirectText: "", accessTokenTtl: 120 })).session_policy).toEqual({
      access_token_ttl: 120,
    });
  });

  it("dedupes redirect lines", () => {
    expect(parseRedirects(" https://a.example/cb \nhttps://a.example/cb\n")).toEqual(["https://a.example/cb"]);
  });
});
