import { describe, it, expect, vi, afterEach } from "vitest";
import { generateKeyPairSync, createVerify } from "node:crypto";
import { makeAppJwt, handleExchangeVerify, handleExchangeDeleteBranch } from "../src/registry/routes/github-app";

// The durable-verifier central half. Two hazard-bearing pieces, both credential-
// free here: (1) the App JWT — if the RS256 signature or the PKCS#1→PKCS#8 wrap
// is wrong, GitHub rejects every installation-token mint and no .life can verify;
// (2) /exchange/verify — the delegated nonce read the vault trusts to prove
// repo-control, so a false "ok" is an auth bypass and a false "not ok" bricks boot.

// A real RSA keypair; private side as PKCS#1 ("BEGIN RSA PRIVATE KEY") — the
// exact format GitHub hands out App keys.
const kp = generateKeyPairSync("rsa", { modulusLength: 2048 });
const APP_PKCS1_PEM = kp.privateKey.export({ type: "pkcs1", format: "pem" }) as string;
const APP_PUB_PEM = kp.publicKey.export({ type: "spki", format: "pem" }) as string;

function makeKV(seed: Record<string, string> = {}) {
  const m = new Map(Object.entries(seed));
  return {
    get: async (k: string) => (m.has(k) ? m.get(k)! : null),
    put: async (k: string, v: string) => void m.set(k, v),
    delete: async (k: string) => void m.delete(k),
    _m: m,
  } as any;
}
const baseEnv = (kv = makeKV({ "ghapp:id": "424242", "ghapp:pem": APP_PKCS1_PEM })) =>
  ({ KNOWN_KV: kv, PUBLIC_URL: "https://known.life" } as any);

const POST = (body: unknown) =>
  new Request("https://known.life/exchange/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": "1.2.3.4" },
    body: JSON.stringify(body),
  });

afterEach(() => vi.restoreAllMocks());

describe("makeAppJwt", () => {
  it("signs a valid RS256 JWT verifiable against the App public key (PKCS#1 import correct)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await makeAppJwt("424242", APP_PKCS1_PEM, now);
    const [h, pl, sig] = jwt.split(".");
    expect(jwt.split(".").length).toBe(3);
    const v = createVerify("RSA-SHA256");
    v.update(`${h}.${pl}`);
    const sigBuf = Buffer.from(sig.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    expect(v.verify(APP_PUB_PEM, sigBuf)).toBe(true);
    const claims = JSON.parse(Buffer.from(pl.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString());
    expect(claims.iss).toBe("424242");
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(600);
  });
});

// A GitHub mock: installation lookup, token mint, nonce read, ref delete.
function ghMock(opts: { installed?: boolean; nonceContent?: string | null } = {}) {
  const { installed = true, nonceContent = null } = opts;
  const deleted: string[] = [];
  let mintedJwt: string | null = null;
  const fetchMock = vi.fn(async (url: any, init: any = {}) => {
    const u = String(url);
    const auth = (init.headers?.Authorization || "").replace(/^Bearer\s+/, "");
    if (/\/repos\/[^?]+\/installation$/.test(u)) {
      mintedJwt = auth;
      return installed
        ? new Response(JSON.stringify({ id: 99 }), { status: 200 })
        : new Response("Not Found", { status: 404 });
    }
    if (/\/app\/installations\/[^/]+\/access_tokens$/.test(u) && init.method === "POST") {
      return new Response(JSON.stringify({ token: "inst-tok" }), { status: 200 });
    }
    const m = u.match(/\/repos\/(.+?)\/contents\/(.+?)\?ref=(.+)$/);
    if (m && (init.method ?? "GET") === "GET") {
      expect(auth).toBe("inst-tok"); // nonce read MUST use the installation token
      return nonceContent === null
        ? new Response("Not Found", { status: 404 })
        : new Response(nonceContent, { status: 200 });
    }
    if (/\/git\/refs\/heads\//.test(u) && init.method === "DELETE") {
      deleted.push(u);
      return new Response(null, { status: 204 });
    }
    return new Response("unexpected", { status: 500 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return { deleted, getJwt: () => mintedJwt };
}

describe("handleExchangeVerify", () => {
  it("ok:true when the nonce matches, using a freshly minted installation token", async () => {
    const m = ghMock({ nonceContent: "the-nonce" });
    const r = await handleExchangeVerify(POST({ repo: "o/r", ref: "life-bootstrap/aabbccdd", path: "x", nonce: "the-nonce" }), baseEnv());
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ ok: true });
    // the App JWT presented to GitHub verifies against our key
    const v = createVerify("RSA-SHA256");
    const [h, pl, sig] = m.getJwt()!.split(".");
    v.update(`${h}.${pl}`);
    expect(v.verify(APP_PUB_PEM, Buffer.from(sig.replace(/-/g, "+").replace(/_/g, "/"), "base64"))).toBe(true);
    expect(m.deleted.length).toBe(1); // the throwaway life-bootstrap branch is reaped
  });

  it("ok:false on a nonce mismatch — no false positive (auth bypass guard)", async () => {
    const m = ghMock({ nonceContent: "WRONG" });
    const r = await handleExchangeVerify(POST({ repo: "o/r", ref: "life-bootstrap/aabbccdd", path: "x", nonce: "the-nonce" }), baseEnv());
    expect(await r.json()).toMatchObject({ ok: false });
    expect(m.deleted.length).toBe(0); // never reap on a failed verify
  });

  it("reports not_installed (not an error) when the App isn't on the repo", async () => {
    ghMock({ installed: false });
    const r = await handleExchangeVerify(POST({ repo: "o/r", ref: "life-bootstrap/aabbccdd", path: "x", nonce: "n" }), baseEnv());
    expect(await r.json()).toMatchObject({ ok: false, reason: "not_installed" });
  });

  it("503 when the verifier App is not registered", async () => {
    const r = await handleExchangeVerify(POST({ repo: "o/r", ref: "r", path: "x", nonce: "n" }), baseEnv(makeKV()));
    expect(r.status).toBe(503);
  });

  it("400 on a malformed repo (no path traversal / injection)", async () => {
    const r = await handleExchangeVerify(POST({ repo: "../etc", ref: "r", path: "x", nonce: "n" }), baseEnv());
    expect(r.status).toBe(400);
  });

  it("does NOT reap a non-bootstrap ref even on a match (scoped deletion)", async () => {
    const m = ghMock({ nonceContent: "n" });
    const r = await handleExchangeVerify(POST({ repo: "o/r", ref: "main", path: "x", nonce: "n" }), baseEnv());
    expect(await r.json()).toMatchObject({ ok: true });
    expect(m.deleted.length).toBe(0);
  });
});

// A GitHub mock for delete-branch: pulls (merge check), repo (default_branch),
// compare, and the ref DELETE.
function delMock(opts: { installed?: boolean; mergedPr?: boolean; aheadBy?: number } = {}) {
  const { installed = true, mergedPr = false, aheadBy = 5 } = opts;
  const deleted: string[] = [];
  const fetchMock = vi.fn(async (url: any, init: any = {}) => {
    const u = String(url);
    if (/\/repos\/[^?]+\/installation$/.test(u)) {
      return installed ? new Response(JSON.stringify({ id: 7 }), { status: 200 }) : new Response("", { status: 404 });
    }
    if (/\/app\/installations\/[^/]+\/access_tokens$/.test(u) && init.method === "POST") {
      return new Response(JSON.stringify({ token: "del-tok" }), { status: 200 });
    }
    if (/\/repos\/[^/]+\/[^/]+\/pulls\?/.test(u)) {
      return new Response(JSON.stringify(mergedPr ? [{ merged_at: "2026-01-01T00:00:00Z" }] : []), { status: 200 });
    }
    if (/\/compare\//.test(u)) {
      return new Response(JSON.stringify({ ahead_by: aheadBy, files: [{ filename: "x" }], total_commits: 1 }), { status: 200 });
    }
    if (/\/repos\/[^/]+\/[^/]+$/.test(u.split("?")[0]) && (init.method ?? "GET") === "GET") {
      return new Response(JSON.stringify({ default_branch: "main" }), { status: 200 });
    }
    if (/\/git\/refs\/heads\//.test(u) && init.method === "DELETE") { deleted.push(u); return new Response(null, { status: 204 }); }
    return new Response("unexpected", { status: 500 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return { deleted };
}
const DELPOST = (body: unknown) =>
  new Request("https://known.life/exchange/delete-branch", { method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": "9.9.9.9" }, body: JSON.stringify(body) });

describe("handleExchangeDeleteBranch", () => {
  it("deletes a scratch life-bootstrap/* branch with no merge check", async () => {
    const m = delMock();
    const r = await handleExchangeDeleteBranch(DELPOST({ repo: "o/r", branch: "life-bootstrap/aabbccdd" }), baseEnv());
    expect(await r.json()).toMatchObject({ ok: true });
    expect(m.deleted.length).toBe(1);
  });
  it("deletes a MERGED claude/* branch (PR merged)", async () => {
    const m = delMock({ mergedPr: true });
    const r = await handleExchangeDeleteBranch(DELPOST({ repo: "o/r", branch: "claude/done" }), baseEnv());
    expect(await r.json()).toMatchObject({ ok: true });
    expect(m.deleted.length).toBe(1);
  });
  it("refuses an UNMERGED claude/* branch (409, no delete) — never lose work", async () => {
    const m = delMock({ mergedPr: false, aheadBy: 5 });
    const r = await handleExchangeDeleteBranch(DELPOST({ repo: "o/r", branch: "claude/wip" }), baseEnv());
    expect(r.status).toBe(409);
    expect(m.deleted.length).toBe(0);
  });
  it("deletes a claude/* branch with no content change (ahead_by 0)", async () => {
    const m = delMock({ mergedPr: false, aheadBy: 0 });
    const r = await handleExchangeDeleteBranch(DELPOST({ repo: "o/r", branch: "claude/noise" }), baseEnv());
    expect(await r.json()).toMatchObject({ ok: true });
    expect(m.deleted.length).toBe(1);
  });
  it("refuses a non-deletable ref (403)", async () => {
    delMock();
    const r = await handleExchangeDeleteBranch(DELPOST({ repo: "o/r", branch: "main" }), baseEnv());
    expect(r.status).toBe(403);
  });
  it("503 when the App is not registered", async () => {
    delMock();
    const r = await handleExchangeDeleteBranch(DELPOST({ repo: "o/r", branch: "claude/x" }), baseEnv(makeKV()));
    expect(r.status).toBe(503);
  });
});
