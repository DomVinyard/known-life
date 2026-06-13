import type { Env } from "../lib/types";
import { checkRate } from "../lib/ratelimit";
import { verifyGithubIdentity } from "../lib/lifekey-verify.mjs";

/**
 * /setup/github-app + /exchange/verify — the durable verifier, central half.
 *
 * The `secrets` vault's /exchange proves repo-control by reading a pushed nonce
 * back from the (private) repo. Doing that needs a GitHub credential. The vault
 * used to hold a captured user OAuth token (rots on revoke). The durable answer
 * is a GitHub App: known.life operates ONE App, holds its private key HERE (a
 * Worker secret, never in any user's vault), and the vault DELEGATES the nonce
 * read to /exchange/verify. A `.life` activates the durable verifier with a
 * single install consent — no token to create, paste, or store.
 *
 * Three surfaces:
 *   GET  /setup/github-app          one-time owner bootstrap: auto-POST a GitHub
 *                                   App *manifest* to github.com so the owner
 *                                   creates the known.life App in one click.
 *   GET  /setup/github-app/callback manifest conversion → store app id + pem.
 *   POST /exchange/verify           { repo, ref, path, nonce } → mint an
 *                                   installation token for repo, read the nonce,
 *                                   reap the throwaway branch, return { ok }.
 *
 * The App key lives only at central; this is the "durable creds at central, not
 * in the ephemeral container or the user's vault" invariant from
 * onboarding-bootstrap.md.
 */

const GH = "https://api.github.com";
// contents:write — write the merge commit (merge-pr) and reap throwaway branches
// (delete-branch); metadata:read — installation lookup. NO checks:read: green-
// gating merge-pr is the agent's job (it reads check-runs via the github MCP),
// because adding an App permission needs a manual owner re-accept with no API to
// automate it — so the merge spine stays inside the permissions already granted.
const APP_PERMS = { contents: "write", metadata: "read" } as const;
const STATE_TTL_S = 600;
const DELETABLE_REF = /^life-bootstrap\/[a-f0-9]{8,}$/;

// KNOWN_KV keys for the one known.life App.
const K_APP_ID = "ghapp:id";
const K_APP_PEM = "ghapp:pem";
const K_APP_SLUG = "ghapp:slug";
const K_STATE = (s: string) => `ghapp:state:${s}`;

// ── credential-free crypto: an App JWT (RS256), ported from the vault worker ──
// (validated there against a real RS256 verify). GitHub issues App keys as
// PKCS#1; Web Crypto imports only PKCS#8, so wrap before importKey.
function b64urlFromBytes(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlFromString(s: string): string {
  return btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function derLength(n: number): number[] {
  if (n < 0x80) return [n];
  const out: number[] = [];
  let x = n;
  while (x > 0) { out.unshift(x & 0xff); x >>= 8; }
  return [0x80 | out.length, ...out];
}
function pkcs1ToPkcs8(pkcs1: Uint8Array): Uint8Array {
  const version = [0x02, 0x01, 0x00];
  const algId = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
  const octet = [0x04, ...derLength(pkcs1.length), ...Array.from(pkcs1)];
  const seq = [...version, ...algId, ...octet];
  return new Uint8Array([0x30, ...derLength(seq.length), ...seq]);
}
async function importAppKey(pem: string): Promise<CryptoKey> {
  const isPkcs1 = /BEGIN RSA PRIVATE KEY/.test(pem);
  const body = pem.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/\s+/g, "");
  const raw = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  const der = isPkcs1 ? pkcs1ToPkcs8(raw) : raw;
  return crypto.subtle.importKey("pkcs8", der.buffer as ArrayBuffer, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
}
export async function makeAppJwt(appId: string, pem: string, now = Math.floor(Date.now() / 1000)): Promise<string> {
  const header = b64urlFromString(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64urlFromString(JSON.stringify({ iat: now - 30, exp: now + 540, iss: String(appId) }));
  const data = `${header}.${payload}`;
  const key = await importAppKey(pem);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(data));
  return `${data}.${b64urlFromBytes(new Uint8Array(sig))}`;
}
const ghHeaders = (auth: string) => ({
  Authorization: `Bearer ${auth}`,
  Accept: "application/vnd.github+json",
  "User-Agent": "known-life-verifier",
});

// The GitHub App manifest — the form github.com renders for the one-click create.
function manifest(env: Env) {
  return {
    name: `known-life-verifier`,
    url: env.PUBLIC_URL,
    hook_attributes: { url: `${env.PUBLIC_URL}/setup/github-app/webhook`, active: false },
    redirect_url: `${env.PUBLIC_URL}/setup/github-app/callback`,
    public: false, // owner-only to start; flip to true (+ domain verification) to serve every .life
    default_permissions: APP_PERMS,
    default_events: [] as string[],
  };
}

// GET /setup/github-app — render the auto-POST manifest form (one click → create).
export async function handleAppManifestStart(req: Request, env: Env): Promise<Response> {
  const existing = await env.KNOWN_KV.get(K_APP_SLUG);
  if (existing) {
    return htmlResp(200, page("known.life App already registered",
      `The known.life verifier App <code>${esc(existing)}</code> is already set up. ` +
      `<p><a href="https://github.com/apps/${esc(existing)}/installations/new">Install it on a repository →</a></p>`));
  }
  const state = crypto.randomUUID().replace(/-/g, "");
  await env.KNOWN_KV.put(K_STATE(state), "1", { expirationTtl: STATE_TTL_S });
  const m = JSON.stringify(manifest(env));
  // Auto-submitting form: one tap lands the user on GitHub's pre-filled
  // "Create GitHub App" consent.
  return htmlResp(200, `<!doctype html><meta charset=utf-8>
<title>Create the known.life verifier App</title>
<body style="font-family:system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem">
<h1>Create the known.life verifier App</h1>
<p>One click registers a GitHub App that lets known.life prove repo-control for
the secrets vault — no token to create or paste.</p>
<form id=f action="https://github.com/settings/apps/new?state=${esc(state)}" method="post">
  <input type="hidden" name="manifest" value='${esc(m)}'>
  <button type="submit" style="font-size:1.1rem;padding:.6rem 1.2rem">Create the GitHub App →</button>
</form>
<script>document.getElementById('f')</script>
</body>`);
}

// GET /setup/github-app/callback?code=&state= — convert the manifest, store the App.
export async function handleAppManifestCallback(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) return htmlResp(400, page("Missing code", "The GitHub redirect was missing its code."));
  const seen = await env.KNOWN_KV.get(K_STATE(state));
  if (!seen) return htmlResp(400, page("Expired", "That registration link expired — start again at /setup/github-app."));
  await env.KNOWN_KV.delete(K_STATE(state));

  // Never overwrite an existing registration. The App private key is the single
  // central credential behind every .life's /exchange; silently replacing it
  // (a leaked/raced state token, or a fresh registration after KV churn) would
  // hijack or DoS the verifier for all .lifes. Registration is one-time; rotation
  // must be an explicit, deliberate operator op, never a callback side effect.
  // Checked BEFORE the manifest conversion so a refused attempt makes no GitHub call.
  const alreadyRegistered = await env.KNOWN_KV.get(K_APP_SLUG);
  if (alreadyRegistered) {
    return htmlResp(409, page("Already registered",
      `The known.life verifier App <code>${esc(alreadyRegistered)}</code> is already registered. ` +
      `Refusing to overwrite the central App credential. Rotation is a deliberate operator action.`));
  }

  const r = await fetch(`${GH}/app-manifests/${encodeURIComponent(code)}/conversions`, {
    method: "POST",
    headers: { Accept: "application/vnd.github+json", "User-Agent": "known-life-verifier" },
  });
  if (!r.ok) return htmlResp(502, page("GitHub error", `Manifest conversion failed (${r.status}). The code is valid for one hour — try again.`));
  const app = await r.json() as { id: number; pem: string; slug: string; html_url?: string };
  if (!app.id || !app.pem || !app.slug) return htmlResp(502, page("Bad response", "GitHub did not return the App credentials."));

  await env.KNOWN_KV.put(K_APP_ID, String(app.id));
  await env.KNOWN_KV.put(K_APP_PEM, app.pem);
  await env.KNOWN_KV.put(K_APP_SLUG, app.slug);

  return htmlResp(200, page("known.life App created",
    `The verifier App <code>${esc(app.slug)}</code> is registered. ` +
    `<p><strong><a href="https://github.com/apps/${esc(app.slug)}/installations/new">Install it on your .life repository →</a></strong></p>` +
    `<p>After installing, the vault's durable verifier activates — no token to paste.</p>`));
}

// Mint an installation token for a repo from the known.life App. Returns the
// token, or { notInstalled } when the App isn't on the repo, or null on error/
// not-registered. Shared by /exchange/verify and /exchange/delete-branch.
async function installationToken(env: Env, repo: string): Promise<{ token: string } | { notInstalled: true } | null> {
  const appId = await env.KNOWN_KV.get(K_APP_ID);
  const pem = await env.KNOWN_KV.get(K_APP_PEM);
  if (!appId || !pem) return null;
  let jwt: string;
  try { jwt = await makeAppJwt(appId, pem); } catch { return null; }
  const inst = await fetch(`${GH}/repos/${repo}/installation`, { headers: ghHeaders(jwt) });
  if (inst.status === 404) return { notInstalled: true };
  if (!inst.ok) return null;
  const installationId = String(((await inst.json()) as { id: number }).id);
  // Narrow the minted token to THIS repo + only the perms the App holds
  // (site-security-audit #5): an installation-wide token could touch every repo
  // in the installation, but every delegated op (verify/delete-branch/merge-pr)
  // acts on exactly `repo`. `repositories` takes bare names; APP_PERMS is the
  // App's full grant, so requesting it is always a valid subset. Behaviourally
  // identical on a single-repo install (the dogfood) — verified via /exchange.
  const repoName = repo.split("/")[1];
  const tokRes = await fetch(`${GH}/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: { ...ghHeaders(jwt), "Content-Type": "application/json" },
    body: JSON.stringify({ repositories: [repoName], permissions: APP_PERMS }),
  });
  if (!tokRes.ok) return null;
  return { token: ((await tokRes.json()) as { token: string }).token };
}

const repoOk = (repo: unknown): repo is string =>
  typeof repo === "string" && /^[\w.-]+\/[\w.-]+$/.test(repo) && !repo.split("/").some((p) => p === "." || p === "..");

// ── caller-auth: the vault proves it acts FOR the repo owner ──────────────────
// /exchange/{verify,delete-branch} are open to the internet; their primitives
// are neutered but a caller could still spend the central App's GitHub quota (or
// DoS a public repo's branch reap). We authenticate the caller without a shared
// secret: the vault signs its request with the OWNER's lifekey
// (LIFEKEY_PRIVATE_KEY, held in the vault's KV; the public half is on
// github.com/<owner>.keys), and we verify that signature here against those
// public keys. No shared secret to leak; works from a fresh .life (the vault
// holds the owner's key before its first /exchange). The signed message is
// domain-separated and bound to (repo, subject, ts) so a signature can't be
// replayed across actions, repos, or — beyond the skew window — time. MUST
// byte-match the vault signer (secrets gene src/worker.js `callerAuthMessage`).
const CALLER_AUTH_SKEW_S = 300;
export function callerAuthMessage(action: string, repo: string, subject: string, ts: number): string {
  return `known.life/exchange/${action}\n${repo}\n${subject}\n${ts}`;
}
async function verifyCaller(action: string, repo: string, subject: string, sig: unknown, ts: unknown): Promise<boolean> {
  if (typeof sig !== "string" || !sig) return false;
  if (typeof ts !== "number" || !Number.isFinite(ts)) return false;
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > CALLER_AUTH_SKEW_S) return false;
  const owner = repo.split("/")[0];
  const msg = callerAuthMessage(action, repo, subject, ts);
  const res = await verifyGithubIdentity(owner, msg, sig);
  return !!res.ok;
}

// POST /exchange/verify { repo, ref, path, nonce } — the delegated nonce read.
// The vault calls this instead of holding a GitHub credential itself.
export async function handleExchangeVerify(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rl = await checkRate(env, `ghverify:${ip}`, 120, 60);
  if (!rl.ok) return json(429, { ok: false, error: "rate_limited" });

  const body = await req.json().catch(() => null) as { repo?: string; ref?: string; path?: string; nonce?: string; sig?: string; ts?: number } | null;
  const repo = body?.repo, ref = body?.ref, path = body?.path, nonce = body?.nonce;
  if (!repoOk(repo) || !ref || !path || !nonce) {
    return json(400, { ok: false, error: "repo, ref, path, nonce required" });
  }
  // Least-privilege: pin the read to the canonical bootstrap location for this
  // nonce. The vault protocol always writes the nonce to `.life-exchange/<nonce>`
  // on a `life-bootstrap/<nonce>` branch (nonce = 48 hex from randomHex(24)) and
  // asks central to read THAT — nothing else. Enforcing it here keeps this
  // endpoint from being an open content-equality oracle: without the pin any
  // internet caller could ask central to read an ARBITRARY path/ref on any
  // App-installed repo and learn whether that file equals a supplied guess.
  // Central's App token is the only reader (the vault holds no GitHub credential),
  // so it must be confined to the protocol's own throwaway file.
  if (!/^[a-f0-9]{8,}$/.test(nonce) || ref !== `life-bootstrap/${nonce}` || path !== `.life-exchange/${nonce}`) {
    return json(400, { ok: false, error: "ref/path must be the canonical bootstrap location for nonce" });
  }
  // Caller-auth BEFORE any GitHub call: an unauthenticated request never spends
  // the central App's quota. The vault signs (repo, nonce, ts) with the owner's
  // lifekey; we verify against github.com/<owner>.keys.
  if (!(await verifyCaller("verify", repo, nonce, body?.sig, body?.ts))) {
    return json(401, { ok: false, error: "caller auth failed" });
  }

  const tok = await installationToken(env, repo);
  if (tok === null) return json(503, { ok: false, error: "verifier app not registered" });
  if ("notInstalled" in tok) return json(200, { ok: false, reason: "not_installed" });
  const instTok = tok.token;

  // Read the nonce back. One re-read absorbs GitHub's read-after-write window.
  let ok = false;
  for (let attempt = 0; attempt < 2 && !ok; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, 2000));
    const rr = await fetch(`${GH}/repos/${repo}/contents/${path}?ref=${encodeURIComponent(ref)}`, {
      headers: { Authorization: `Bearer ${instTok}`, Accept: "application/vnd.github.raw", "User-Agent": "known-life-verifier" },
    });
    if (rr.ok) ok = (await rr.text()).trim() === nonce;
  }

  // Reap the throwaway bootstrap branch (the vault delegated, so it has no token).
  if (ok && DELETABLE_REF.test(ref)) {
    await fetch(`${GH}/repos/${repo}/git/refs/heads/${ref}`, { method: "DELETE", headers: ghHeaders(instTok) }).catch(() => {});
  }
  return json(200, { ok });
}

// GET /exchange/installed?repo=<owner/repo> → { installed, install_url } — the
// onboarding gate. A fresh .life's vault is delegation-only, so it can't verify
// until the known.life App is installed on its repo, and only the repo owner can
// grant that (one consent tap). `setup` polls this until installed; `install_url`
// is the one-tap link to surface.
export async function handleAppInstalled(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rl = await checkRate(env, `ghinstalled:${ip}`, 120, 60);
  if (!rl.ok) return json(429, { installed: false, error: "rate_limited" });
  const repo = new URL(req.url).searchParams.get("repo");
  const slug = await env.KNOWN_KV.get(K_APP_SLUG);
  const install_url = slug ? `https://github.com/apps/${slug}/installations/new` : null;
  if (!install_url) return json(503, { installed: false, error: "verifier app not registered", install_url });
  if (!repoOk(repo)) return json(400, { installed: false, error: "repo required (owner/repo)", install_url });
  const tok = await installationToken(env, repo);
  const installed = tok !== null && !("notInstalled" in tok);
  return json(200, { installed, install_url });
}

// POST /exchange/delete-branch { repo, branch } — delete a spent branch a
// session can't (the harness git proxy 403s ref deletion). The brokered-ops
// pattern the vault used, with its GitHub credential swapped to the App. Guarded
// HARD: only merged `claude/*` or scratch `life-bootstrap/*` — unmerged work can
// never be lost (content-free commit noise can). The merge guard is verbatim
// from the vault's old handleGitDeleteBranch.
const DELETABLE_BRANCH = /^(claude|life-bootstrap)\/[A-Za-z0-9._/-]+$/;
export async function handleExchangeDeleteBranch(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rl = await checkRate(env, `ghdelbranch:${ip}`, 60, 60);
  if (!rl.ok) return json(429, { ok: false, error: "rate_limited" });

  const body = await req.json().catch(() => null) as { repo?: string; branch?: string; sig?: string; ts?: number } | null;
  const repo = body?.repo, branch = body?.branch;
  if (!repoOk(repo) || typeof branch !== "string" || !branch) return json(400, { ok: false, error: "repo, branch required" });
  if (!DELETABLE_BRANCH.test(branch) || branch.includes("..")) {
    return json(403, { ok: false, error: "refusing: only claude/* or life-bootstrap/* branches are deletable" });
  }
  // Caller-auth BEFORE any GitHub call (same scheme as /exchange/verify): the
  // vault signs (repo, branch, ts) with the owner's lifekey.
  if (!(await verifyCaller("delete-branch", repo, branch, body?.sig, body?.ts))) {
    return json(401, { ok: false, error: "caller auth failed" });
  }

  const tok = await installationToken(env, repo);
  if (tok === null) return json(503, { ok: false, error: "verifier app not registered" });
  if ("notInstalled" in tok) return json(200, { ok: false, reason: "not_installed" });
  const gh = (p: string, init?: RequestInit) => fetch(`${GH}/repos/${repo}${p}`, { ...init, headers: { ...ghHeaders(tok.token), ...(init && init.headers) } });

  // Merge guard for claude/* (life-bootstrap/* is throwaway scratch — skip).
  if (branch.startsWith("claude/")) {
    const owner = repo.split("/")[0];
    let merged = false;
    const prRes = await gh(`/pulls?head=${encodeURIComponent(`${owner}:${branch}`)}&state=all&per_page=100`);
    if (prRes.ok) {
      const prs = await prRes.json().catch(() => []) as Array<{ merged_at?: string }>;
      merged = Array.isArray(prs) && prs.some((pr) => pr && pr.merged_at);
    }
    if (!merged) {
      const repoRes = await gh("");
      const def = repoRes.ok ? ((await repoRes.json().catch(() => ({}))) as { default_branch?: string }).default_branch : null;
      if (def) {
        const cmp = await gh(`/compare/${encodeURIComponent(def)}...${encodeURIComponent(branch)}`);
        if (cmp.ok) {
          const c = await cmp.json().catch(() => ({})) as { ahead_by?: number; files?: unknown[]; total_commits?: number };
          // ahead_by 0: tip already reachable from the default branch. files []:
          // the branch introduces no content change vs default (stale evolve
          // noise) — deleting loses commit metadata only, never content.
          merged = !!c && (c.ahead_by === 0 || (Array.isArray(c.files) && c.files.length === 0 && (c.total_commits ?? 0) <= 250));
        }
      }
    }
    if (!merged) return json(409, { ok: false, error: "refusing: branch is not merged into the default branch" });
  }

  const del = await gh(`/git/refs/heads/${branch}`, { method: "DELETE" });
  const already = del.status === 422; // ref already gone
  const ok = del.status === 204 || already;
  if (!ok) return json(502, { ok: false, error: `github delete failed (${del.status})` });
  return json(200, { ok: true, branch, already_gone: already });
}

// POST /exchange/merge-pr { repo, pr, branch, sha } — squash-merge a PR a session
// can't merge itself (no GitHub token of its own; the in-session MCP merge dance
// is trap-ridden — casing traps, auto-merge that won't arm, no green-success
// webhook). Same App-on-central spine + owner-lifekey caller-auth as
// /exchange/delete-branch.
//
// GREEN-GATING IS THE CALLER'S JOB, not central's. Reading a head's CI status
// (check-runs) needs a `checks:read` App permission GitHub only grants via a
// manual owner re-accept in the App UI (declined — and there is no API to
// automate it). But the agent already reads check-runs RELIABLY via the github
// MCP (`get_check_runs`); that was never the flaky part — the MERGE mechanics
// were. So the canonical flow is: the agent polls check-runs green via MCP, THEN
// invokes merge-pr. Central does the one thing the session can't.
//
// Central enforces what its held permissions (contents:write, metadata:read)
// allow, and the SHA-pin is the load-bearing safety:
//   - `branch` must be a claude/* head (a guardrail; the caller is already
//     owner-authenticated, and merging is a non-destructive owner-capable act).
//   - the merge is PINNED to `sha` (the merge API's `sha` guard) AND the caller's
//     lifekey signature is bound to that same `sha` — so central squash-merges
//     EXACTLY the commit the agent verified green, and a head that moved since
//     (new commits → new sha) 409s instead of landing an unverified commit.
// contents:write (held) authorizes the merge; no check-runs read, no new grant.
const MERGEABLE_HEAD = /^claude\/[A-Za-z0-9._/-]+$/;
export async function handleExchangeMergePR(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rl = await checkRate(env, `ghmergepr:${ip}`, 60, 60);
  if (!rl.ok) return json(429, { ok: false, error: "rate_limited" });

  const body = await req.json().catch(() => null) as { repo?: string; pr?: number; branch?: string; sha?: string; sig?: string; ts?: number } | null;
  const repo = body?.repo, pr = body?.pr, branch = body?.branch, sha = body?.sha;
  if (!repoOk(repo)) return json(400, { ok: false, error: "repo required (owner/repo)" });
  if (!Number.isInteger(pr) || (pr as number) <= 0) return json(400, { ok: false, error: "pr (positive integer) required" });
  if (typeof branch !== "string" || !MERGEABLE_HEAD.test(branch) || branch.includes("..")) {
    return json(403, { ok: false, error: "refusing: only claude/* PRs are mergeable" });
  }
  if (typeof sha !== "string" || !/^[0-9a-f]{40}$/.test(sha)) {
    return json(400, { ok: false, error: "sha (40 hex — the head commit you verified green) required" });
  }
  // Caller-auth BEFORE any GitHub call (same scheme as /exchange/delete-branch):
  // the vault signs (repo, sha, ts) with the owner's lifekey. Binding the subject
  // to the SHA pins the signature to the exact commit being merged — it can't be
  // replayed to merge a later, unverified head.
  if (!(await verifyCaller("merge-pr", repo, sha, body?.sig, body?.ts))) {
    return json(401, { ok: false, error: "caller auth failed" });
  }

  const tok = await installationToken(env, repo);
  if (tok === null) return json(503, { ok: false, error: "verifier app not registered" });
  if ("notInstalled" in tok) return json(200, { ok: false, reason: "not_installed" });
  const gh = (p: string, init?: RequestInit) => fetch(`${GH}/repos/${repo}${p}`, { ...init, headers: { ...ghHeaders(tok.token), ...(init && init.headers) } });

  // Squash-merge, pinned to the caller-verified SHA (the agent confirmed CI green
  // on this exact commit before invoking).
  const mr = await gh(`/pulls/${pr}/merge`, { method: "PUT", body: JSON.stringify({ merge_method: "squash", sha }) });
  if (mr.status === 200) {
    const j = await mr.json().catch(() => ({})) as { sha?: string };
    return json(200, { ok: true, merged: true, sha: j.sha ?? sha });
  }
  if (mr.status === 409) return json(409, { ok: false, error: "head moved since you verified it — re-check CI and re-run merge-pr" });
  if (mr.status === 405) {
    const j = await mr.json().catch(() => ({})) as { message?: string };
    return json(409, { ok: false, error: `not mergeable: ${j.message ?? "branch protection or conflict"}` });
  }
  if (mr.status === 403) {
    return json(403, { ok: false, error: "merge forbidden — the App likely lacks contents:write; re-accept the App permission update" });
  }
  const j = await mr.json().catch(() => ({})) as { message?: string };
  return json(502, { ok: false, error: `merge failed (${mr.status})${j.message ? ": " + j.message : ""}` });
}

// ── helpers ──────────────────────────────────────────────────────────────────
function esc(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string));
}
function page(title: string, bodyHtml: string): string {
  return `<!doctype html><meta charset=utf-8><title>${esc(title)}</title>
<body style="font-family:system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem">
<h1>${esc(title)}</h1>${bodyHtml}</body>`;
}
function htmlResp(status: number, body: string): Response {
  return new Response(body, { status, headers: { "Content-Type": "text/html; charset=utf-8" } });
}
function json(status: number, data: unknown): Response {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
