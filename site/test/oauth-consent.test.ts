import { describe, it, expect } from "vitest";
import { handleAuthorize, handleConsent } from "../src/registry/routes/mcp-oauth";
import { issueSsoSession, SSO_COOKIE } from "../src/registry/lib/jwt";

// The silent-SSO open-redirect defense: a known.life SSO cookie must NOT silently
// mint an auth code for an arbitrary external redirect_uri (that hands whoever
// controls the origin a bearer for the user). Same-origin + localhost stay silent;
// an unknown external origin gets a one-time consent; a consented origin is silent
// again. Without this, a lured SSO'd victim clicking a crafted /authorize link
// leaked a code to the attacker.

const KEY = "test-signing-key-deterministic-0123456789abcdef";
function makeKV(seed: Record<string, string> = {}) {
  const m = new Map(Object.entries(seed));
  return {
    get: async (k: string) => (m.has(k) ? m.get(k)! : null),
    put: async (k: string, v: string) => void m.set(k, v),
    delete: async (k: string) => void m.delete(k),
    _m: m,
  } as any;
}
const env = (kv = makeKV()) =>
  ({ KNOWN_KV: kv, PUBLIC_URL: "https://known.life", JWT_SIGNING_KEY: KEY,
     KNOWN_OAUTH_CLIENT_ID: "cid", KNOWN_OAUTH_CLIENT_SECRET: "sec" } as any);

const ssoCookie = async (e: any, sub = "github:octocat") =>
  `${SSO_COOKIE}=${await issueSsoSession(sub, e)}`;

const authUrl = (redirect: string) =>
  `https://known.life/api/oauth/authorize?response_type=code&client_id=c&redirect_uri=${encodeURIComponent(redirect)}&code_challenge=abc&code_challenge_method=S256`;

const authReq = async (e: any, redirect: string) =>
  new Request(authUrl(redirect), { headers: { Cookie: await ssoCookie(e) } });

describe("OAuth silent-SSO open-redirect defense", () => {
  it("silently mints for a SAME-ORIGIN redirect (302 + code)", async () => {
    const e = env();
    const r = await handleAuthorize(await authReq(e, "https://known.life/cb"), e);
    expect(r.status).toBe(302);
    expect(new URL(r.headers.get("location")!).searchParams.get("code")).toBeTruthy();
  });

  it("silently mints for a localhost redirect (MCP client on the user's machine)", async () => {
    const e = env();
    const r = await handleAuthorize(await authReq(e, "http://localhost:8976/cb"), e);
    expect(r.status).toBe(302);
    expect(new URL(r.headers.get("location")!).searchParams.get("code")).toBeTruthy();
  });

  it("does NOT silently mint for an unknown EXTERNAL origin — shows consent, leaks no code", async () => {
    const e = env();
    const r = await handleAuthorize(await authReq(e, "https://evil.example/cb"), e);
    expect(r.status).toBe(200);
    expect(r.headers.get("Content-Type")).toContain("text/html");
    expect(r.headers.get("X-Frame-Options")).toBe("DENY"); // no clickjacking the consent
    // The page must NOT set Referrer-Policy: no-referrer — that forces Origin:null
    // on its own form POST, which Astro's checkOrigin rejects (the consent could
    // then never be approved for any external origin). `same-origin` sends a real
    // Origin to /consent while still leaking no Referer cross-origin.
    expect(r.headers.get("Referrer-Policy")).not.toBe("no-referrer");
    expect(r.headers.get("Referrer-Policy")).toBe("same-origin");
    const body = await r.text();
    expect(body).toContain("https://evil.example");
    expect(body).not.toMatch(/[?&]code=/); // no auth code anywhere in the page
  });

  it("silently mints once the external origin has been consented", async () => {
    const e = env(makeKV({ "oauth-consent:github:octocat:https://app.example": "1" }));
    const r = await handleAuthorize(await authReq(e, "https://app.example/cb"), e);
    expect(r.status).toBe(302);
    expect(new URL(r.headers.get("location")!).searchParams.get("code")).toBeTruthy();
  });

  const consentPost = async (e: any, token: string, decision: string, sub = "github:octocat") =>
    new Request("https://known.life/api/oauth/consent", {
      method: "POST",
      headers: { Cookie: await ssoCookie(e, sub), "Content-Type": "application/x-www-form-urlencoded" },
      body: `token=${token}&decision=${decision}`,
    });

  it("consent APPROVE → remembers origin + mints code with state preserved", async () => {
    const kv = makeKV(); const e = env(kv);
    await kv.put("oauth-consent-req:tok1", JSON.stringify(
      { client_id: "c", redirect_uri: "https://app.example/cb", state: "xyz", code_challenge: "abc", subject: "github:octocat" }));
    const r = await handleConsent(await consentPost(e, "tok1", "approve"), e);
    expect(r.status).toBe(302);
    const loc = new URL(r.headers.get("location")!);
    expect(loc.origin + loc.pathname).toBe("https://app.example/cb");
    expect(loc.searchParams.get("code")).toBeTruthy();
    expect(loc.searchParams.get("state")).toBe("xyz");
    expect(await kv.get("oauth-consent:github:octocat:https://app.example")).toBe("1");
    expect(await kv.get("oauth-consent-req:tok1")).toBeNull(); // single-use
  });

  it("consent DENY → access_denied, no code, origin not remembered", async () => {
    const kv = makeKV(); const e = env(kv);
    await kv.put("oauth-consent-req:tok2", JSON.stringify(
      { client_id: "c", redirect_uri: "https://app.example/cb", state: "s", code_challenge: "abc", subject: "github:octocat" }));
    const r = await handleConsent(await consentPost(e, "tok2", "deny"), e);
    expect(r.status).toBe(302);
    const loc = new URL(r.headers.get("location")!);
    expect(loc.searchParams.get("error")).toBe("access_denied");
    expect(loc.searchParams.get("code")).toBeNull();
    expect(await kv.get("oauth-consent:github:octocat:https://app.example")).toBeNull();
  });

  it("a DIFFERENT identity cannot approve another user's consent request (400, not remembered)", async () => {
    const kv = makeKV(); const e = env(kv);
    await kv.put("oauth-consent-req:tok3", JSON.stringify(
      { client_id: "c", redirect_uri: "https://app.example/cb", state: null, code_challenge: "abc", subject: "github:victim" }));
    const r = await handleConsent(await consentPost(e, "tok3", "approve", "github:attacker"), e);
    expect(r.status).toBe(400);
    expect(await kv.get("oauth-consent:github:victim:https://app.example")).toBeNull();
  });

  it("an expired/unknown consent token is refused", async () => {
    const e = env();
    const r = await handleConsent(await consentPost(e, "nope", "approve"), e);
    expect(r.status).toBe(400);
  });
});
