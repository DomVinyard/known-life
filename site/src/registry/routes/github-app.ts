import type { Env } from "../lib/types";
import { checkRate } from "../lib/ratelimit";

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
  const tokRes = await fetch(`${GH}/app/installations/${installationId}/access_tokens`, { method: "POST", headers: ghHeaders(jwt) });
  if (!tokRes.ok) return null;
  return { token: ((await tokRes.json()) as { token: string }).token };
}

const repoOk = (repo: unknown): repo is string =>
  typeof repo === "string" && /^[\w.-]+\/[\w.-]+$/.test(repo) && !repo.split("/").some((p) => p === "." || p === "..");

// POST /exchange/verify { repo, ref, path, nonce } — the delegated nonce read.
// The vault calls this instead of holding a GitHub credential itself.
export async function handleExchangeVerify(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rl = await checkRate(env, `ghverify:${ip}`, 120, 60);
  if (!rl.ok) return json(429, { ok: false, error: "rate_limited" });

  const body = await req.json().catch(() => null) as { repo?: string; ref?: string; path?: string; nonce?: string } | null;
  const repo = body?.repo, ref = body?.ref, path = body?.path, nonce = body?.nonce;
  if (!repoOk(repo) || !ref || !path || !nonce) {
    return json(400, { ok: false, error: "repo, ref, path, nonce required" });
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

  const body = await req.json().catch(() => null) as { repo?: string; branch?: string } | null;
  const repo = body?.repo, branch = body?.branch;
  if (!repoOk(repo) || typeof branch !== "string" || !branch) return json(400, { ok: false, error: "repo, branch required" });
  if (!DELETABLE_BRANCH.test(branch) || branch.includes("..")) {
    return json(403, { ok: false, error: "refusing: only claude/* or life-bootstrap/* branches are deletable" });
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
