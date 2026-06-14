import { describe, it, expect, beforeEach } from "vitest";
import {
  s256,
  genVerifier,
  buildAuthorizeUrl,
  encryptSecret,
  decryptSecret,
  putGrant,
  getGrant,
  CF_OAUTH_SCOPES,
  type CfGrant,
} from "../src/registry/lib/cf-oauth";
import { handleCfOAuthStart, handleCfOAuthStatus, handleCfOAuthToken, parseDownscope } from "../src/registry/routes/cloudflare-oauth";
import { issueRegistryToken } from "../src/registry/lib/jwt";

// The CF OAuth flow is the paste-free infra-onboarding credential path: a wrong
// PKCE challenge, a leaked-in-the-clear refresh token, or a start route that
// mints a consent URL for an unauthenticated caller would each be a security
// hole. These tests pin the pure logic credential-free (no live Cloudflare).

// Minimal in-memory KV mock — get/put/delete, TTL ignored (tests don't wait).
class MockKV {
  private m = new Map<string, string>();
  async get(k: string): Promise<string | null> {
    return this.m.has(k) ? this.m.get(k)! : null;
  }
  async put(k: string, v: string): Promise<void> {
    this.m.set(k, v);
  }
  async delete(k: string): Promise<void> {
    this.m.delete(k);
  }
}

const SIGNING = "test-signing-key-deterministic-0123456789abcdef";
const env = (over: Record<string, unknown> = {}) =>
  ({
    JWT_SIGNING_KEY: SIGNING,
    PUBLIC_URL: "https://known.life",
    CF_OAUTH_CLIENT_ID: "12eb82cbtest",
    CF_OAUTH_CLIENT_SECRET: "shh-secret",
    KNOWN_KV: new MockKV(),
    ...over,
  }) as any;

describe("PKCE s256", () => {
  it("matches the RFC 7636 reference vector", async () => {
    // verifier → challenge from RFC 7636 Appendix B.
    expect(await s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe(
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
  });

  it("genVerifier produces a valid-length verifier (43–128 chars)", () => {
    const v = genVerifier();
    expect(v.length).toBeGreaterThanOrEqual(43);
    expect(v.length).toBeLessThanOrEqual(128);
  });
});

describe("authorize URL", () => {
  it("carries the OAuth params and the registered scope set", () => {
    const u = new URL(buildAuthorizeUrl(env(), { state: "ST", codeChallenge: "CH", redirectUri: "https://known.life/oauth/cf/callback" }));
    expect(u.origin + u.pathname).toBe("https://dash.cloudflare.com/oauth2/auth");
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("client_id")).toBe("12eb82cbtest");
    expect(u.searchParams.get("redirect_uri")).toBe("https://known.life/oauth/cf/callback");
    expect(u.searchParams.get("state")).toBe("ST");
    expect(u.searchParams.get("code_challenge")).toBe("CH");
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    const scope = u.searchParams.get("scope") ?? "";
    expect(scope.split(" ")).toEqual(CF_OAUTH_SCOPES);
    expect(scope).toContain("offline_access");
  });
});

describe("refresh-token encryption at rest", () => {
  it("round-trips through encrypt/decrypt", async () => {
    const e = env();
    const blob = await encryptSecret(e, "refresh-abc-123");
    expect(blob).not.toContain("refresh-abc-123"); // not stored in the clear
    expect(await decryptSecret(e, blob)).toBe("refresh-abc-123");
  });

  it("fails to decrypt a tampered blob", async () => {
    const e = env();
    const blob = await encryptSecret(e, "refresh-abc-123");
    const [iv, ct] = blob.split(".");
    const tampered = `${iv}.${ct.slice(0, -2)}AA`;
    await expect(decryptSecret(e, tampered)).rejects.toBeTruthy();
  });

  it("a different signing key cannot decrypt", async () => {
    const blob = await encryptSecret(env(), "refresh-abc-123");
    await expect(decryptSecret(env({ JWT_SIGNING_KEY: "another-key-padded-to-thirty-two-bytes-xxxx" }), blob)).rejects.toBeTruthy();
  });
});

describe("per-user grant store", () => {
  it("round-trips a grant through KV", async () => {
    const e = env();
    const grant: CfGrant = {
      refresh_token_enc: "iv.ct",
      account_id: "acc1",
      account_name: "Acme",
      accounts: [{ id: "acc1", name: "Acme" }],
      updated_at: 1,
    };
    await putGrant(e, "octocat", grant);
    expect(await getGrant(e, "octocat")).toEqual(grant);
    expect(await getGrant(e, "nobody")).toBeNull();
  });

  it("is case-insensitive in the login (GitHub logins are) — a grant stored under one casing is found under another", async () => {
    // The bug caught live 2026-06-13: a device-flow session (GitHub-canonical
    // "Octocat") couldn't see a grant a lifekey session stored as "octocat".
    const e = env();
    const grant: CfGrant = {
      refresh_token_enc: "iv.ct",
      account_id: "acc1",
      account_name: "Acme",
      accounts: [{ id: "acc1", name: "Acme" }],
      updated_at: 1,
    };
    await putGrant(e, "Octocat", grant);
    expect(await getGrant(e, "octocat")).toEqual(grant);
    expect(await getGrant(e, "OCTOCAT")).toEqual(grant);
  });
});

describe("POST /api/setup/cf-oauth/start", () => {
  const post = (e: any, headers: Record<string, string> = {}) =>
    handleCfOAuthStart(new Request("https://known.life/api/setup/cf-oauth/start", { method: "POST", headers }), e);

  it("503 when the CF client is not configured", async () => {
    const res = await post(env({ CF_OAUTH_CLIENT_ID: undefined, CF_OAUTH_CLIENT_SECRET: undefined }));
    expect(res.status).toBe(503);
  });

  it("401 without a bearer", async () => {
    expect((await post(env())).status).toBe(401);
  });

  it("401 with a non-github subject is impossible — a valid github bearer is required", async () => {
    const bad = await post(env(), { Authorization: "Bearer not-a-real-jwt" });
    expect(bad.status).toBe(401);
  });

  it("200 with a valid github bearer → returns a consent URL whose challenge matches the stashed verifier", async () => {
    const e = env();
    const bearer = await issueRegistryToken("github:octocat", e);
    const res = await post(e, { Authorization: `Bearer ${bearer}` });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { authorize_url: string; state: string };
    const u = new URL(body.authorize_url);
    expect(u.searchParams.get("state")).toBe(body.state);

    // The pending entry must hold the verifier whose S256 equals the URL challenge,
    // bound to the proven login.
    const pendingRaw = await e.KNOWN_KV.get(`cf-oauth:pending:${body.state}`);
    expect(pendingRaw).toBeTruthy();
    const pending = JSON.parse(pendingRaw!) as { login: string; code_verifier: string };
    expect(pending.login).toBe("octocat");
    expect(await s256(pending.code_verifier)).toBe(u.searchParams.get("code_challenge"));
  });
});

describe("GET /api/setup/cf-oauth/status", () => {
  const get = (e: any, headers: Record<string, string> = {}) =>
    handleCfOAuthStatus(new Request("https://known.life/api/setup/cf-oauth/status", { headers }), e);

  it("401 without a bearer", async () => {
    expect((await get(env())).status).toBe(401);
  });

  it("connected:false for a github bearer with no stored grant (no network)", async () => {
    const e = env();
    const bearer = await issueRegistryToken("github:octocat", e);
    const res = await get(e, { Authorization: `Bearer ${bearer}` });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ connected: false });
  });
});

describe("POST /api/setup/cf-oauth/token (the brokered mint surface)", () => {
  const post = (e: any, headers: Record<string, string> = {}) =>
    handleCfOAuthToken(new Request("https://known.life/api/setup/cf-oauth/token", { method: "POST", headers }), e);

  it("503 when the CF client is not configured", async () => {
    const res = await post(env({ CF_OAUTH_CLIENT_ID: undefined, CF_OAUTH_CLIENT_SECRET: undefined }));
    expect(res.status).toBe(503);
  });

  it("401 without a bearer", async () => {
    expect((await post(env())).status).toBe(401);
  });

  it("401 with an invalid bearer", async () => {
    expect((await post(env(), { Authorization: "Bearer not-a-real-jwt" })).status).toBe(401);
  });

  it("409 not_connected for a valid github bearer with no stored grant (no network)", async () => {
    const e = env();
    const bearer = await issueRegistryToken("github:octocat", e);
    const res = await post(e, { Authorization: `Bearer ${bearer}` });
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toBe("not_connected");
  });
});

describe("parseDownscope (optional least-privilege subset)", () => {
  const reg = ["workers-scripts.read", "queues.read", "ai.read"];
  it("omitted scope → no downscope (full grant)", () => {
    expect(parseDownscope({}, reg)).toEqual({ scope: undefined, bad: [] });
    expect(parseDownscope({ scope: "" }, reg)).toEqual({ scope: undefined, bad: [] });
  });
  it("accepts a string or array subset, deduped + space-joined", () => {
    expect(parseDownscope({ scope: "queues.read workers-scripts.read" }, reg).scope).toBe("queues.read workers-scripts.read");
    expect(parseDownscope({ scope: ["ai.read", "ai.read"] }, reg).scope).toBe("ai.read");
  });
  it("flags any unregistered id and yields no scope (no form-param injection)", () => {
    const r = parseDownscope({ scope: "queues.read not-a-scope d1.write" }, reg);
    expect(r.bad).toEqual(["not-a-scope", "d1.write"]);
    expect(r.scope).toBeUndefined();
  });
});
