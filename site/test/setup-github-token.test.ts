import { describe, it, expect } from "vitest";
import { handleSetupGithubToken } from "../src/registry/routes/setup";
import { issueRegistryToken } from "../src/registry/lib/jwt";

// The decoupled GitHub-token delivery for the OAuth setup flow (the non-CF half
// of the retired `redeem`). It hands the device-flow-cached GitHub token back to
// the JWT-bound setup process — so a missing bearer, a wrong bearer, or a leak to
// an unauthenticated caller would each be a hole. These pin the gating logic.

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
  ({ JWT_SIGNING_KEY: SIGNING, KNOWN_KV: new MockKV(), ...over }) as any;

const post = (e: any, headers: Record<string, string> = {}) =>
  handleSetupGithubToken(new Request("https://known.life/api/setup/github-token", { method: "POST", headers }), e);

describe("POST /api/setup/github-token", () => {
  it("401 without a bearer", async () => {
    expect((await post(env())).status).toBe(401);
  });

  it("401 with an invalid bearer", async () => {
    expect((await post(env(), { Authorization: "Bearer not-a-real-jwt" })).status).toBe(401);
  });

  it("410 when no GitHub token is cached (device flow expired / not run)", async () => {
    const e = env();
    const bearer = await issueRegistryToken("github:octocat", e);
    const res = await post(e, { Authorization: `Bearer ${bearer}` });
    expect(res.status).toBe(410);
    expect(((await res.json()) as { error: string }).error).toBe("gh_token_expired");
  });

  it("200 returns the cached GitHub token bound to the proven login", async () => {
    const e = env();
    await e.KNOWN_KV.put("gh:tok:octocat", JSON.stringify({ token: "gho_abc123", scope: "repo,workflow" }));
    const bearer = await issueRegistryToken("github:octocat", e);
    const res = await post(e, { Authorization: `Bearer ${bearer}` });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { github_login: string; github_token: string; scope: string };
    expect(body.github_login).toBe("octocat");
    expect(body.github_token).toBe("gho_abc123");
    expect(body.scope).toBe("repo,workflow");
  });

  it("reads the token for the bearer's login only — a different login's cache is invisible", async () => {
    const e = env();
    await e.KNOWN_KV.put("gh:tok:someone-else", JSON.stringify({ token: "gho_secret", scope: "repo" }));
    const bearer = await issueRegistryToken("github:octocat", e);
    const res = await post(e, { Authorization: `Bearer ${bearer}` });
    expect(res.status).toBe(410); // octocat has no cache; cannot see someone-else's
  });
});
