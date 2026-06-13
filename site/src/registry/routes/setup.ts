import type { Env } from "../lib/types";
import { verifyToken } from "../lib/jwt";
import { checkRate } from "../lib/ratelimit";
import { seedActionsSecrets } from "../lib/gh-secrets";

/**
 * /setup — the cold-start credential flow.
 *
 * In Life the AGENT drives every command (the user never operates a terminal),
 * so onboarding is agent-driven: the agent device-flows into a known.life JWT
 * (sub: github:<login>), and the OAuth bridge caches the GitHub access token at
 * gh:tok:<login> as a side-effect of the elevated-scope grant. The only
 * credential it can't obtain that way — the Cloudflare token (CF has no device
 * flow) — is collected via a single-use, JWT-bound browser drop-box. The
 * credential bundle is delivered back to the setup process over a
 * JWT-authenticated POST (/api/setup/redeem), bound to the originating login —
 * never baked into a fetchable artifact. See the section below for the contract.
 *
 * (An older browser flow — a hosted page that POSTed creds and handed back a
 * `curl <handle> | sh` with the credentials spliced into install.sh — was
 * removed: it delivered creds to a bare terminal that holds no known.life
 * identity, so the handle was the only auth and it could never be
 * identity-bound. It served the pre-Life "human runs commands on a laptop"
 * model; the agent cf-drop flow below replaces it.)
 */

const CF_DROP_TTL_S = 600;          // 10 min — the agent flow's CF drop window
const CF_VERIFY = "https://api.cloudflare.com/client/v4/user/tokens/verify";
const CF_ACCOUNTS = "https://api.cloudflare.com/client/v4/accounts";

function randomHandle(bytes: number): string {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return Array.from(b, (n) => n.toString(16).padStart(2, "0")).join("");
}

function json(status: number, data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status, headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}
function htmlResp(status: number, body: string): Response {
  return new Response(body, {
    status, headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

// ============================================================================
// Agent-driven setup: device-flow JWT + browser drop-box for the CF token
// ============================================================================
//
// The AGENT is the originator: it has already device-flowed into a known.life
// JWT (sub: github:<login>) — see routes/mcp-oauth.ts handleDeviceCode/
// tokenDeviceCode. The OAuth bridge cached the GitHub access token at
// gh:tok:<login> as a side-effect of the elevated-scope grant. The only
// credential still missing is the Cloudflare token, and Cloudflare has no device
// flow. Solution: a single-use browser drop-box on this origin, JWT-bound at
// creation.
//
//   POST /api/setup/cf-drop          (Bearer <known.life JWT>)
//     Mints an opaque handle bound to the JWT's login. Returns
//     { handle, drop_url, expires_in }. The agent shows drop_url to the user.
//
//   GET  /setup/cf/<handle>          (public; the handle is the auth)
//     Single-purpose HTML form: one password field, one Save button.
//
//   POST /setup/cf/<handle>          (form-encoded)
//     Validates the token against Cloudflare /user/tokens/verify, lists
//     accounts via /accounts (must be exactly one — see the multi-account
//     gotcha in the handover note), updates the drop to status: "filled".
//
//   POST /api/setup/redeem           (Bearer <known.life JWT>)
//     Single-use. Verifies JWT.sub === drop.login, drop is filled, and
//     gh:tok:<login> is still cached. Returns the full credential bundle
//     directly to the setup process. Deletes the drop entry on success;
//     leaves the gh:tok cache to expire on its own 1h TTL (setup completes
//     in <5 min — no need to evict early). If the body carries `repo_slug`
//     (the setup gene reads it off the git remote), the CF credentials are
//     also sealed into that repo's Actions secrets (lib/gh-secrets) so the
//     generated deploy.yml deploys from the first push.
//
// The CF token never reaches the agent transcript (it lives in this Worker
// memory + KV briefly, then flows direct to the setup process via TLS). The
// GH token never reaches either the agent transcript OR the user's browser.

interface CfDrop {
  login: string;                  // JWT.sub at creation time
  status: "pending" | "filled";
  created_at: number;
  // Populated on submit:
  cf_token?: string;
  cf_account_id?: string;
  cf_account_name?: string;
}

// --- POST /api/setup/cf-drop ---

export async function handleCreateCfDrop(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rl = await checkRate(env, `setup-cfdrop:${ip}`, 20, 60 * 60);
  if (!rl.ok) return json(429, { error: "rate_limited", retry_after_s: rl.retryAfter });

  const authHeader = req.headers.get("Authorization") ?? "";
  const tok = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  const subject = tok ? await verifyToken(tok, env) : null;
  if (!subject || !subject.startsWith("github:")) return json(401, { error: "unauthorized" });
  const login = subject.slice("github:".length);

  const handle = randomHandle(24);
  const drop: CfDrop = { login, status: "pending", created_at: Date.now() };
  await env.KNOWN_KV.put(`setup:cf-drop:${handle}`, JSON.stringify(drop), {
    expirationTtl: CF_DROP_TTL_S,
  });

  const origin = env.PUBLIC_URL ?? new URL(req.url).origin;
  return json(200, {
    ok: true,
    handle,
    drop_url: `${origin}/setup/cf/${handle}`,
    expires_in: CF_DROP_TTL_S,
  });
}

// --- GET /setup/cf/<handle> --- (form)

export async function handleCfDropForm(_req: Request, env: Env, handle: string): Promise<Response> {
  if (!/^[a-f0-9]{48}$/.test(handle)) return htmlResp(404, errorPage("invalid drop handle"));
  const raw = await env.KNOWN_KV.get(`setup:cf-drop:${handle}`);
  if (!raw) return htmlResp(410, errorPage("This drop has expired or been used already. Re-run setup in your agent to get a fresh link."));
  const drop = JSON.parse(raw) as CfDrop;
  if (drop.status === "filled") {
    return htmlResp(200, infoPage(
      "Already saved",
      "This drop has already been filled. Return to your agent — it should be picking up the credentials on its next run.",
    ));
  }
  return htmlResp(200, cfDropForm(handle, drop.login));
}

// --- POST /setup/cf/<handle> --- (form submission)

export async function handleCfDropSubmit(req: Request, env: Env, handle: string): Promise<Response> {
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rl = await checkRate(env, `setup-cfsubmit:${ip}`, 30, 60 * 60);
  if (!rl.ok) return htmlResp(429, errorPage("Too many attempts. Wait a minute and try again."));

  if (!/^[a-f0-9]{48}$/.test(handle)) return htmlResp(404, errorPage("invalid drop handle"));
  const raw = await env.KNOWN_KV.get(`setup:cf-drop:${handle}`);
  if (!raw) return htmlResp(410, errorPage("This drop has expired."));
  const drop = JSON.parse(raw) as CfDrop;

  // Parse form body.
  const ct = req.headers.get("Content-Type") ?? "";
  if (!ct.includes("application/x-www-form-urlencoded"))
    return htmlResp(400, errorPage("Bad form submission"));
  const form = new URLSearchParams(await req.text());
  const cfTok = (form.get("cf_token") || "").trim();
  if (!cfTok) return htmlResp(400, cfDropForm(handle, drop.login, "Paste a token, then click Save."));

  // 1. Verify the token is well-formed + active.
  const verifyRes = await fetch(CF_VERIFY, {
    headers: { Authorization: `Bearer ${cfTok}` },
  });
  const verifyBody = await verifyRes.json().catch(() => ({})) as { success?: boolean; result?: { status?: string } };
  if (!verifyRes.ok || !verifyBody.success || verifyBody.result?.status !== "active") {
    return htmlResp(400, cfDropForm(handle, drop.login,
      "That token didn't verify. Create one with the 'Edit Cloudflare Workers' template and add D1, Workers KV, R2 Storage permissions.",
    ));
  }

  // 2. List accounts the token can see. Exactly one → use it. Zero → broken
  // token. More than one → ambiguous; we don't auto-pick because the wrong
  // account = vault deployed to the wrong place.
  const accountsRes = await fetch(CF_ACCOUNTS, {
    headers: { Authorization: `Bearer ${cfTok}` },
  });
  const accountsBody = await accountsRes.json().catch(() => ({})) as {
    success?: boolean;
    result?: Array<{ id: string; name: string }>;
  };
  if (!accountsRes.ok || !accountsBody.success || !Array.isArray(accountsBody.result)) {
    return htmlResp(502, cfDropForm(handle, drop.login,
      "Couldn't list Cloudflare accounts with that token. Check the token's Account scope.",
    ));
  }
  const accts = accountsBody.result;
  if (accts.length === 0) {
    return htmlResp(400, cfDropForm(handle, drop.login,
      "Token sees zero Cloudflare accounts. Re-create it scoped to the account that should host this .life's vault.",
    ));
  }
  if (accts.length > 1) {
    const names = accts.map((a) => `${a.name} (${a.id})`).join(", ");
    return htmlResp(400, cfDropForm(handle, drop.login,
      `Token sees ${accts.length} accounts (${names}). Re-create it scoped to a single account so we know where the vault belongs.`,
    ));
  }
  const account = accts[0];

  // 3. Persist filled drop.
  const filled: CfDrop = {
    ...drop,
    status: "filled",
    cf_token: cfTok,
    cf_account_id: account.id,
    cf_account_name: account.name,
  };
  await env.KNOWN_KV.put(`setup:cf-drop:${handle}`, JSON.stringify(filled), {
    expirationTtl: CF_DROP_TTL_S,
  });

  return htmlResp(200, infoPage(
    "Saved",
    `Token saved for Cloudflare account "${escapeHtml(account.name)}". Return to your agent — its next setup run will pick up the credentials and finish provisioning. You can close this tab.`,
  ));
}

// --- POST /api/setup/redeem ---

export async function handleAgentRedeem(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rl = await checkRate(env, `setup-redeem:${ip}`, 60, 60 * 60);
  if (!rl.ok) return json(429, { error: "rate_limited", retry_after_s: rl.retryAfter });

  const authHeader = req.headers.get("Authorization") ?? "";
  const tok = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  const subject = tok ? await verifyToken(tok, env) : null;
  if (!subject || !subject.startsWith("github:")) return json(401, { error: "unauthorized" });
  const login = subject.slice("github:".length);

  const body = await req.json().catch(() => null) as { handle?: string; repo_slug?: string } | null;
  const handle = body?.handle?.trim() ?? "";
  if (!/^[a-f0-9]{48}$/.test(handle)) return json(400, { error: "invalid_handle" });

  const raw = await env.KNOWN_KV.get(`setup:cf-drop:${handle}`);
  if (!raw) return json(404, { error: "no_such_drop", hint: "drop expired or already redeemed; restart setup" });
  const drop = JSON.parse(raw) as CfDrop;

  if (drop.login !== login) return json(403, { error: "mismatch", hint: "this drop belongs to a different login" });
  if (drop.status !== "filled" || !drop.cf_token || !drop.cf_account_id) {
    // Use 202 so polling clients can treat this as "not yet" rather than an
    // error — the script's state machine retries on 202 without resetting.
    return json(202, { error: "not_yet", hint: "user has not submitted the CF token yet" });
  }

  // gh:tok cache may have evicted (1h TTL on the OAuth bridge). If so, the
  // client needs to re-do device flow. 410 distinguishes "your JWT is fine,
  // but the upstream credential it represents is gone" from a plain 401.
  const ghRaw = await env.KNOWN_KV.get(`gh:tok:${login}`);
  if (!ghRaw) return json(410, { error: "gh_token_expired", hint: "OAuth cache expired; restart device flow" });
  const gh = JSON.parse(ghRaw) as { token: string; scope: string };

  // If the caller told us its repo (the setup gene derives it from the git
  // remote), seed the Actions secrets the generated deploy.yml reads so it
  // deploys from the first push. Non-fatal, surfaced.
  let ci: { ok: boolean; error?: string } = { ok: false, error: "no_repo_slug" };
  const slug = (body?.repo_slug || "").trim();
  if (slug) {
    ci = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(slug)
      ? await seedActionsSecrets(gh.token, slug, {
          CLOUDFLARE_API_TOKEN: drop.cf_token,
          CLOUDFLARE_ACCOUNT_ID: drop.cf_account_id,
        })
      : { ok: false, error: "invalid_repo_slug" };
  }

  // Single-use: drop the KV entry before returning. (The gh:tok cache stays
  // — it's on its own 1h TTL and we don't need to evict early.)
  await env.KNOWN_KV.delete(`setup:cf-drop:${handle}`);

  return json(200, {
    ok: true,
    github_login: login,
    github_token: gh.token,
    cloudflare_api_token: drop.cf_token,
    cloudflare_account_id: drop.cf_account_id,
    cloudflare_account_name: drop.cf_account_name ?? null,
    ci_secrets_seeded: ci.ok,
    ...(ci.ok ? {} : { ci_secrets_error: ci.error }),
  });
}

// --- HTML scaffolding ---
//
// Inline, minimal, self-contained. Matches known.life's plain-prose feel —
// no framework, no images, system font stack.

function pageShell(title: string, inner: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} — known.life</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         max-width: 32rem; margin: 4rem auto 2rem; padding: 0 1.25rem; }
  h1 { font-size: 1.25rem; margin: 0 0 .25rem; }
  .sub { color: #666; margin: 0 0 1.5rem; }
  form { display: flex; flex-direction: column; gap: .85rem; }
  label { font-weight: 600; }
  .hint { font-weight: 400; color: #666; font-size: .9em; display: block; margin-top: .2rem; }
  input[type=password] { font: inherit; padding: .55rem .6rem; border: 1px solid #ccc; border-radius: 4px;
                        background: transparent; color: inherit; width: 100%; box-sizing: border-box; }
  button { font: inherit; padding: .55rem 1rem; border: 0; border-radius: 4px;
           background: #111; color: #fff; cursor: pointer; align-self: flex-start; }
  button:hover { background: #333; }
  .primary { display: inline-block; padding: .65rem 1.1rem; margin: .25rem 0 1.5rem;
             background: #111; color: #fff; border-radius: 4px; text-decoration: none;
             font-weight: 600; }
  .primary:hover { background: #333; }
  .error { color: #b00020; background: #b000200f; padding: .6rem .75rem; border-radius: 4px;
           border-left: 3px solid #b00020; }
  .ok { color: #0a6; background: #00aa6610; padding: .6rem .75rem; border-radius: 4px;
        border-left: 3px solid #0a6; }
  a { color: inherit; }
  code { font: .9em ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
         background: #00000010; padding: .1em .35em; border-radius: 3px; }
  @media (prefers-color-scheme: dark) {
    .sub, .hint { color: #999; }
    input[type=password] { border-color: #444; }
    button { background: #eee; color: #000; }
    button:hover { background: #fff; }
    .primary { background: #eee; color: #000; }
    .primary:hover { background: #fff; }
    code { background: #ffffff15; }
  }
</style>
</head>
<body>
${inner}
</body>
</html>`;
}

// Pre-populated Cloudflare API token creation URL. CF's dashboard accepts
// `permissionGroupKeys` as a URL-encoded JSON array; the page opens with the
// four permissions Life needs already ticked. User still has to click
// "Continue to summary" → "Create token" → "Copy" on CF's side (CF doesn't
// short-circuit those), but the manual permission selection is gone. Keys
// pulled from https://developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/
// (workers_scripts, workers_kv_storage, workers_r2, d1).
const CF_CREATE_TOKEN_URL =
  "https://dash.cloudflare.com/profile/api-tokens?" +
  "permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C" +
  "%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C" +
  "%7B%22key%22%3A%22workers_r2%22%2C%22type%22%3A%22edit%22%7D%2C" +
  "%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%5D" +
  "&name=known.life";

function cfDropForm(handle: string, _login: string, errorMsg?: string): string {
  const inner = `
<h1>Connect infrastructure</h1>
<p class="sub">A .life needs an infrastructure provider. Create a Cloudflare API token with the permissions already ticked, paste it below.</p>

<a class="primary" href="${CF_CREATE_TOKEN_URL}" target="_blank" rel="noopener">Create Cloudflare API token →</a>

${errorMsg ? `<p class="error">${escapeHtml(errorMsg)}</p>` : ""}

<form method="POST" action="/setup/cf/${escapeHtml(handle)}">
  <input type="password" name="cf_token" autocomplete="off" placeholder="Paste token here" autofocus required>
  <button type="submit">Save</button>
</form>

<p class="sub" style="margin-top:2rem;font-size:.85em">
  Scope the token to a single Cloudflare account — multi-account tokens can't be used (we wouldn't know which to deploy to).
  Your token goes direct to your agent's setup process via TLS; known.life doesn't store it past this session.
  This link is single-use and expires in 10 minutes.
</p>
`;
  return pageShell("Connect infrastructure", inner);
}

function infoPage(title: string, body: string): string {
  return pageShell(title, `<h1>${escapeHtml(title)}</h1><p class="ok">${escapeHtml(body)}</p>`);
}

function errorPage(msg: string): string {
  return pageShell("Error", `<h1>Something went wrong</h1><p class="error">${escapeHtml(msg)}</p>`);
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string
  ));
}
