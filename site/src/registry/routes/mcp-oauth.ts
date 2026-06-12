import type { Env } from "../lib/types";
import { issueRegistryToken, issueSsoSession, verifySsoSession, SSO_COOKIE, SSO_COOKIE_TTL_S } from "../lib/jwt";
import { getOrCreateGithubAccount } from "../lib/db";
import { checkRate } from "../lib/ratelimit";

/**
 * MCP OAuth bridge — RFC-6749 authorization-code-with-PKCE on this origin,
 * with github.com as the upstream IdP. Standard MCP OAuth 2.1 flow (rev
 * 2025-03-26): client discovers `/.well-known/oauth-protected-resource`,
 * fetches `/.well-known/oauth-authorization-server`, redirects the user
 * through `/api/oauth/authorize` → github.com → `/api/oauth/github-callback`,
 * then exchanges the authorization code at `/api/oauth/token` for a known.life
 * bearer.
 *
 * The minted bearer is the SAME JWT the lifekey path mints (sub: `github:<login>`).
 * So every existing write endpoint — /api/publish, /api/claim, /api/deprecate,
 * /api/unpublish, the MCP tools/call dispatcher — accepts it transparently.
 * No second auth path, no shared admin secret: identity is the GitHub login the
 * user proved by completing the OAuth round-trip.
 *
 * Storage: short-lived KV entries keyed by an opaque value and expired by KV
 * TTL — no DB schema for in-flight authorizations. Server-side code-with-PKCE
 * (we issue the auth code, client proves possession of the verifier).
 *
 * Public clients only — MCP clients can't safely store a client secret, so
 * the token endpoint authenticates via PKCE (RFC 7636), not client_secret.
 * The client_id is opaque; we don't enforce a registration table (no DCR yet).
 * redirect_uri is validated as well-formed http(s)/localhost — defence
 * against open-redirect abuse without forcing every MCP client to pre-register.
 */

const STATE_TTL_S = 600;           // 10 min — user has to click through github.com
const AUTH_CODE_TTL_S = 60;        // 60s — typical OAuth one-shot
const GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN = "https://github.com/login/oauth/access_token";
const GITHUB_DEVICE_CODE = "https://github.com/login/device/code";
const GITHUB_USER = "https://api.github.com/user";
const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

interface PendingAuth {
  client_id: string;
  redirect_uri: string;
  state: string | null;
  code_challenge: string;
  code_challenge_method: "S256";
  scope: string;                   // GitHub scope requested by the initiator
}

interface AuthCode {
  subject: string;                 // `github:<login>` — what the issued JWT will carry
  redirect_uri: string;            // must match the one used at /authorize
  code_challenge: string;          // verified against PKCE code_verifier at /token
  code_challenge_method: "S256";
}

// --- discovery ---

export function handleProtectedResourceMetadata(req: Request, env: Env): Response {
  const origin = serverOrigin(req, env);
  return json(200, {
    resource: origin,
    authorization_servers: [origin],
    scopes_supported: ["write"],
    bearer_methods_supported: ["header"],
  });
}

export function handleAuthorizationServerMetadata(req: Request, env: Env): Response {
  const origin = serverOrigin(req, env);
  return json(200, {
    issuer: origin,
    authorization_endpoint: `${origin}/api/oauth/authorize`,
    token_endpoint: `${origin}/api/oauth/token`,
    device_authorization_endpoint: `${origin}/api/oauth/device-code`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", DEVICE_GRANT],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],   // public clients (PKCE / device)
    scopes_supported: ["write"],
  });
}

// --- authorize: client → us → github.com ---

export async function handleAuthorize(req: Request, env: Env): Promise<Response> {
  if (!env.KNOWN_OAUTH_CLIENT_ID || !env.KNOWN_OAUTH_CLIENT_SECRET) {
    return html(503, "OAuth bridge not configured (KNOWN_OAUTH_CLIENT_ID/SECRET unset).");
  }
  const url = new URL(req.url);
  const q = url.searchParams;
  const response_type = q.get("response_type");
  const client_id = q.get("client_id");
  const redirect_uri = q.get("redirect_uri");
  const state = q.get("state");
  const code_challenge = q.get("code_challenge");
  const code_challenge_method = q.get("code_challenge_method");
  // GitHub scope. MCP wants the minimum (`read:user`); /setup needs `repo` +
  // `workflow` to push (incl. the generated deploy.yml) and `admin:public_key`
  // to register the lifekey. Allow-listed to stop a random client claiming
  // admin:org or other escalations.
  const scopeReq = (q.get("scope") || "read:user").trim();
  if (!isAllowedScope(scopeReq)) return badRequest(`scope '${scopeReq}' not allowed; permitted: ${ALLOWED_SCOPES.join(", ")}`);

  if (response_type !== "code") return badRequest("response_type must be 'code'");
  if (!client_id) return badRequest("client_id required");
  if (!redirect_uri || !isAcceptableRedirect(redirect_uri))
    return badRequest("redirect_uri must be a well-formed http(s) or localhost URL");
  if (!code_challenge) return badRequest("code_challenge required (PKCE)");
  if (code_challenge_method !== "S256") return badRequest("code_challenge_method must be 'S256'");

  // SSO: if this browser already proved its GitHub identity here (the `known_sso`
  // cookie), authenticate SILENTLY — mint the auth code and bounce straight back
  // to the client, no github.com round-trip. This is what makes one login carry
  // across every UI surface a .life deploys.
  const prompt = (q.get("prompt") || "").trim();
  const ssoSubject = await readSsoSubject(req, env);
  if (ssoSubject) {
    // SSO present. Minting a code for redirect_uri and bouncing it there hands
    // whoever controls that origin a bearer for THIS user. A same-origin or
    // localhost target is safe (it's us, or the user's own machine); an external
    // origin is only safe once the user has consented to it. Without this gate a
    // lured SSO'd victim clicking a crafted /authorize?redirect_uri=https://evil…
    // link silently leaks a code to the attacker (open-redirect → bearer).
    const target = new URL(redirect_uri).origin;
    const trusted = isSilentTrusted(redirect_uri, serverOrigin(req, env))
      || (await env.KNOWN_KV.get(`oauth-consent:${ssoSubject}:${target}`)) !== null;
    if (trusted) {
      const code = await mintAuthCode(ssoSubject, { redirect_uri, code_challenge, code_challenge_method: "S256" }, env);
      return Response.redirect(clientRedirect(redirect_uri, code, state), 302);
    }
    if (prompt === "none") {
      // Client asked for silent-only but this external origin isn't consented yet
      // → standard interaction_required so the client surfaces an interactive run.
      const err = new URL(redirect_uri);
      err.searchParams.set("error", "interaction_required");
      if (state) err.searchParams.set("state", state);
      return Response.redirect(err.toString(), 302);
    }
    // First time this user is sent to an external origin — ask once, remember after.
    return renderConsent(env, { client_id, redirect_uri, state, code_challenge, subject: ssoSubject });
  }
  // No SSO session and the client asked for silent-only → standard OIDC error,
  // so the client can fall back to an interactive login. (RFC: login_required.)
  if (prompt === "none") {
    const err = new URL(redirect_uri);
    err.searchParams.set("error", "login_required");
    if (state) err.searchParams.set("state", state);
    return Response.redirect(err.toString(), 302);
  }

  // Mint our own opaque marker; pass it as `state` to GitHub. On the way back,
  // we look this up to recover the original client request.
  const bridgeState = randomToken(24);
  const pending: PendingAuth = { client_id, redirect_uri, state, code_challenge, code_challenge_method, scope: scopeReq };
  await env.KNOWN_KV.put(`mcp-oauth:pending:${bridgeState}`, JSON.stringify(pending), {
    expirationTtl: STATE_TTL_S,
  });

  const origin = serverOrigin(req, env);
  const githubUrl = new URL(GITHUB_AUTHORIZE);
  githubUrl.searchParams.set("client_id", env.KNOWN_OAUTH_CLIENT_ID);
  githubUrl.searchParams.set("redirect_uri", `${origin}/api/oauth/github-callback`);
  githubUrl.searchParams.set("scope", scopeReq);
  githubUrl.searchParams.set("state", bridgeState);
  githubUrl.searchParams.set("allow_signup", "false");
  return Response.redirect(githubUrl.toString(), 302);
}

// --- github callback: github.com → us → client ---

export async function handleGithubCallback(req: Request, env: Env): Promise<Response> {
  if (!env.KNOWN_OAUTH_CLIENT_ID || !env.KNOWN_OAUTH_CLIENT_SECRET) {
    return html(503, "OAuth bridge not configured.");
  }
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const bridgeState = url.searchParams.get("state");
  if (!code || !bridgeState) return badRequest("missing code/state from github");

  const pendingJson = await env.KNOWN_KV.get(`mcp-oauth:pending:${bridgeState}`);
  if (!pendingJson) return badRequest("unknown or expired state");
  await env.KNOWN_KV.delete(`mcp-oauth:pending:${bridgeState}`);   // single-use
  const pending: PendingAuth = JSON.parse(pendingJson);

  // 1. Exchange GitHub code for an upstream access token.
  const tokRes = await fetch(GITHUB_TOKEN, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: env.KNOWN_OAUTH_CLIENT_ID,
      client_secret: env.KNOWN_OAUTH_CLIENT_SECRET,
      code,
      redirect_uri: `${serverOrigin(req, env)}/api/oauth/github-callback`,
    }),
  });
  const tok = await tokRes.json().catch(() => ({})) as { access_token?: string; error?: string };
  if (!tokRes.ok || !tok.access_token) return badRequest(`github token exchange failed: ${tok.error ?? tokRes.status}`);

  // 2. Identify the user via the GitHub user API (stable id + current login).
  const userRes = await fetch(GITHUB_USER, {
    headers: { Authorization: `Bearer ${tok.access_token}`, "User-Agent": "known.life", Accept: "application/json" },
  });
  const user = await userRes.json().catch(() => ({})) as {
    id?: number; login?: string; avatar_url?: string | null; name?: string | null;
  };
  if (!userRes.ok || typeof user.id !== "number" || !user.login)
    return badRequest("github user fetch failed");

  // 3. Bind to a genepool account row (creates one on first sign-in).
  await getOrCreateGithubAccount(env, {
    githubId: user.id,
    login: user.login,
    avatar: user.avatar_url ?? null,
    name: user.name ?? null,
  });

  // 3a. If the upstream scope is beyond `read:user`, cache the GitHub access
  //     token under `gh:tok:<login>` so server-side flows (routes/setup.ts)
  //     can call GitHub APIs as the user without ever exposing the token to
  //     the browser. Same TTL as our minted JWT (1h).
  if (pending.scope !== "read:user") {
    await env.KNOWN_KV.put(
      `gh:tok:${user.login}`,
      JSON.stringify({ token: tok.access_token, scope: pending.scope }),
      { expirationTtl: 3600 },
    );
  }

  // 4. Mint our auth code and — crucially — drop the SSO session cookie, so
  //    every later /authorize from any UI surface authenticates silently.
  const subject = `github:${user.login}`;
  const authCode = await mintAuthCode(subject, pending, env);
  const location = clientRedirect(pending.redirect_uri, authCode, pending.state);
  const sso = await issueSsoSession(subject, env);
  return new Response(null, {
    status: 302,
    headers: {
      Location: location,
      "Set-Cookie": `${SSO_COOKIE}=${sso}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SSO_COOKIE_TTL_S}`,
    },
  });
}

// Store an auth-code binding (single-use, short TTL) and return the opaque code.
// Shared by the GitHub callback and the silent-SSO path in handleAuthorize.
async function mintAuthCode(
  subject: string,
  pending: { redirect_uri: string; code_challenge: string; code_challenge_method: "S256" },
  env: Env,
): Promise<string> {
  const authCode = randomToken(32);
  const binding: AuthCode = {
    subject,
    redirect_uri: pending.redirect_uri,
    code_challenge: pending.code_challenge,
    code_challenge_method: pending.code_challenge_method,
  };
  await env.KNOWN_KV.put(`mcp-oauth:code:${authCode}`, JSON.stringify(binding), {
    expirationTtl: AUTH_CODE_TTL_S,
  });
  return authCode;
}

function clientRedirect(redirectUri: string, code: string, state: string | null): string {
  const r = new URL(redirectUri);
  r.searchParams.set("code", code);
  if (state) r.searchParams.set("state", state);
  return r.toString();
}

async function readSsoSubject(req: Request, env: Env): Promise<string | null> {
  const raw = getCookieValue(req, SSO_COOKIE);
  return raw ? verifySsoSession(raw, env) : null;
}

function getCookieValue(req: Request, name: string): string | null {
  const header = req.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return null;
}

// --- device flow: headless clients (CLI, agent sessions with no browser) ---
//
// 1. Client POSTs to /api/oauth/device-code → we forward to github.com/login/
//    device/code with our client_id, return GitHub's {device_code, user_code,
//    verification_uri, expires_in, interval} verbatim so the client can show
//    user_code + verification_uri to the human.
// 2. Human opens verification_uri on any browser, signs in to github.com,
//    enters user_code, approves "Sign in with known.life".
// 3. Client polls /api/oauth/token with grant_type=urn:...:device_code &
//    device_code=<token>. We forward each poll to github.com/login/oauth/
//    access_token; while pending, we surface authorization_pending / slow_down;
//    once GitHub returns an access_token we identify the user and mint OUR JWT.
//    The GitHub access_token is discarded — we only need it to call /user once.

export async function handleDeviceCode(req: Request, env: Env): Promise<Response> {
  if (!env.KNOWN_OAUTH_CLIENT_ID) return oauthError(503, "server_error", "OAuth bridge not configured");
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rl = await checkRate(env, `oauth-device:${ip}`, 30, 60 * 60);
  if (!rl.ok) return json(429, { error: "rate_limited", retry_after_s: rl.retryAfter });

  // Allow the client to request scope beyond `read:user`. The `setup` flow
  // needs `repo,workflow,admin:public_key,read:user` to push (incl. the
  // generated deploy.yml), register the lifekey, and read back the /exchange
  // nonce; MCP-only clients can omit scope and get the identity-only default.
  // Allow-listed via `isAllowedScope` so a random client can't smuggle
  // `admin:org` or other escalations into the consent screen.
  const reqBody = await req.json().catch(() => ({})) as { scope?: string };
  const scope = (reqBody.scope || "read:user").trim();
  if (!isAllowedScope(scope)) {
    return oauthError(400, "invalid_scope", `scope '${scope}' not allowed; permitted: ${ALLOWED_SCOPES.join(", ")}`);
  }

  const res = await fetch(GITHUB_DEVICE_CODE, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: env.KNOWN_OAUTH_CLIENT_ID, scope }),
  });
  const body = await res.json().catch(() => ({})) as Record<string, unknown>;
  if (!res.ok) return oauthError(res.status, "server_error", `github device endpoint: ${JSON.stringify(body)}`);
  // GitHub returns: device_code, user_code, verification_uri,
  // verification_uri_complete?, expires_in, interval. Pass through.
  return json(200, body);
}

// --- token: client exchanges code+verifier for the known.life bearer ---

export async function handleToken(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rl = await checkRate(env, `oauth-token:${ip}`, 60, 60);
  if (!rl.ok) return json(429, { error: "rate_limited", retry_after_s: rl.retryAfter });

  let body: URLSearchParams;
  const ct = req.headers.get("Content-Type") ?? "";
  if (ct.includes("application/x-www-form-urlencoded")) {
    body = new URLSearchParams(await req.text());
  } else if (ct.includes("application/json")) {
    const j = await req.json().catch(() => ({})) as Record<string, string>;
    body = new URLSearchParams(j);
  } else {
    return oauthError(400, "invalid_request", "Content-Type must be form-urlencoded or json");
  }

  const grant_type = body.get("grant_type");
  if (grant_type === "authorization_code") return tokenAuthCode(body, env);
  if (grant_type === DEVICE_GRANT) return tokenDeviceCode(body, env);
  return oauthError(400, "unsupported_grant_type", `got '${grant_type}'`);
}

async function tokenAuthCode(body: URLSearchParams, env: Env): Promise<Response> {
  const code = body.get("code");
  const redirect_uri = body.get("redirect_uri");
  const code_verifier = body.get("code_verifier");
  if (!code || !redirect_uri || !code_verifier) return oauthError(400, "invalid_request", "code, redirect_uri, code_verifier required");

  const bindingJson = await env.KNOWN_KV.get(`mcp-oauth:code:${code}`);
  if (!bindingJson) return oauthError(400, "invalid_grant", "code unknown or expired");
  await env.KNOWN_KV.delete(`mcp-oauth:code:${code}`);   // single-use
  const binding: AuthCode = JSON.parse(bindingJson);

  if (binding.redirect_uri !== redirect_uri)
    return oauthError(400, "invalid_grant", "redirect_uri mismatch");

  const expected = await s256(code_verifier);
  if (expected !== binding.code_challenge)
    return oauthError(400, "invalid_grant", "PKCE verifier did not match challenge");

  return mintBearer(binding.subject, env);
}

async function tokenDeviceCode(body: URLSearchParams, env: Env): Promise<Response> {
  if (!env.KNOWN_OAUTH_CLIENT_ID) return oauthError(503, "server_error", "OAuth bridge not configured");
  const device_code = body.get("device_code");
  if (!device_code) return oauthError(400, "invalid_request", "device_code required");

  // Forward the poll to GitHub. GitHub's response semantics: while pending,
  // returns 200 with `error: authorization_pending` (or slow_down); on success,
  // returns 200 with access_token. We pass the polling errors through verbatim
  // (RFC 8628 §3.5) so the client's backoff loop continues to work, and on
  // success we discard GitHub's token after fetching the user identity.
  const ghRes = await fetch(GITHUB_TOKEN, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: env.KNOWN_OAUTH_CLIENT_ID,
      device_code,
      grant_type: DEVICE_GRANT,
    }),
  });
  const gh = await ghRes.json().catch(() => ({})) as { access_token?: string; scope?: string; error?: string; error_description?: string };
  if (gh.error) {
    // Pass polling-state errors through with their standard codes. Unknown
    // errors land as invalid_grant — the client should stop.
    const passthrough = new Set(["authorization_pending", "slow_down", "access_denied", "expired_token"]);
    return json(passthrough.has(gh.error) ? 400 : 400, { error: gh.error, error_description: gh.error_description ?? "" });
  }
  if (!ghRes.ok || !gh.access_token) return oauthError(400, "invalid_grant", "github device token exchange returned no access_token");

  const userRes = await fetch(GITHUB_USER, {
    headers: { Authorization: `Bearer ${gh.access_token}`, "User-Agent": "known.life", Accept: "application/json" },
  });
  const user = await userRes.json().catch(() => ({})) as { id?: number; login?: string; avatar_url?: string | null; name?: string | null };
  if (!userRes.ok || typeof user.id !== "number" || !user.login)
    return oauthError(400, "invalid_grant", "github user fetch failed");
  await getOrCreateGithubAccount(env, {
    githubId: user.id, login: user.login, avatar: user.avatar_url ?? null, name: user.name ?? null,
  });

  // Mirror the browser-callback path (handleGithubCallback:180-186): when the
  // granted scope is beyond identity-only (`read:user`), cache the upstream
  // access token at `gh:tok:<login>` so server-side flows (setup) can call
  // GitHub APIs as the user without ever exposing the token to the agent
  // transcript. Without this branch, the device-flow path silently breaks
  // `setup` even with the right scope requested — the token would be
  // discarded immediately after the user identity round-trip.
  // GitHub returns granted scope space-separated (e.g. "admin:public_key repo
  // read:user"); we cache as long as anything beyond read:user landed.
  const grantedScopes = (gh.scope || "").split(/[\s,]+/).filter(Boolean);
  const elevated = grantedScopes.some((s: string) => s !== "read:user");
  if (elevated && gh.access_token) {
    await env.KNOWN_KV.put(
      `gh:tok:${user.login}`,
      JSON.stringify({ token: gh.access_token, scope: gh.scope ?? "" }),
      { expirationTtl: 3600 },
    );
  }

  return mintBearer(`github:${user.login}`, env);
}

async function mintBearer(subject: string, env: Env): Promise<Response> {
  const access_token = await issueRegistryToken(subject, env);
  // Mirror jwt.ts's TTL (1h). The MCP client can re-run the flow when it expires.
  return json(200, {
    access_token,
    token_type: "Bearer",
    expires_in: 3600,
    scope: "write",
  });
}

// --- helpers ---

function serverOrigin(req: Request, env: Env): string {
  return env.PUBLIC_URL ?? new URL(req.url).origin;
}

function randomToken(bytes: number): string {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return Array.from(b, (n) => n.toString(16).padStart(2, "0")).join("");
}

async function s256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  // base64url, no padding
  const b = String.fromCharCode(...new Uint8Array(digest));
  return btoa(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Allow-list of GitHub scopes our bridge will request — keeps a random client
// from claiming `admin:org`, `delete_repo`, or other escalations. Comma-
// separated, space-tolerant. `workflow` is required (2026-06-10): without it
// the captured token cannot push `.github/workflows/*`, and the generated
// deploy.yml is the ci-deploy convention's central artifact. The pre-workflow
// sets stay listed so pinned older setup-gene versions remain usable
// (versioning is total) — they just can't push workflow files.
export const ALLOWED_SCOPES = [
  "read:user",                                   // MCP default — identity only
  "repo,workflow,admin:public_key,read:user",    // /setup — push (incl. deploy.yml) + register lifekey
  "repo,workflow,admin:public_key",              // /setup (no identity-only suffix)
  "repo,admin:public_key,read:user",             // pre-workflow setup genes (≤2.20.0)
  "repo,admin:public_key",                       // pre-workflow setup genes (≤2.20.0)
];
export function isAllowedScope(scope: string): boolean {
  const norm = scope.split(",").map((s) => s.trim()).filter(Boolean).sort().join(",");
  return ALLOWED_SCOPES.some((allowed) =>
    allowed.split(",").map((s) => s.trim()).filter(Boolean).sort().join(",") === norm,
  );
}

function isAcceptableRedirect(uri: string): boolean {
  try {
    const u = new URL(uri);
    if (u.protocol === "https:") return true;
    if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) return true;
    return false;
  } catch {
    return false;
  }
}

// --- silent-SSO trust + one-time consent (open-redirect → bearer defense) ---

// A redirect target safe to mint for WITHOUT consent: same-origin as us (it's
// known.life itself) or a loopback address (the code lands on the user's own
// machine, unreachable by a remote attacker). Every other origin must be
// consented once before silent SSO will mint a code for it.
function isSilentTrusted(redirectUri: string, server: string): boolean {
  try {
    const u = new URL(redirectUri);
    if (u.origin === new URL(server).origin) return true;
    return u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "::1";
  } catch {
    return false;
  }
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

function htmlPage(status: number, body: string): Response {
  return new Response(`<!doctype html><meta charset=utf-8>${body}`, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      // The consent click must be deliberate — never framed/clickjacked.
      "X-Frame-Options": "DENY",
      "Content-Security-Policy": "frame-ancestors 'none'",
      "Referrer-Policy": "no-referrer",
    },
  });
}

interface ConsentReq {
  client_id: string;
  redirect_uri: string;
  state: string | null;
  code_challenge: string;
  subject: string;
}

// Render the one-time consent interstitial for a not-yet-trusted external origin.
async function renderConsent(env: Env, r: ConsentReq): Promise<Response> {
  const token = randomToken(24);
  await env.KNOWN_KV.put(`oauth-consent-req:${token}`, JSON.stringify(r), { expirationTtl: STATE_TTL_S });
  const origin = escapeHtml(new URL(r.redirect_uri).origin);
  const login = escapeHtml(r.subject.replace(/^github:/, ""));
  return htmlPage(200, `<title>Sign in · known.life</title>
<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem;line-height:1.55">
<h1>Sign in to a site</h1>
<p><strong>${origin}</strong> wants to sign you in as <strong>@${login}</strong> using your known.life identity.</p>
<p>Approving lets this site act as you on known.life. Only approve if you recognise it.</p>
<form method="post" action="/api/oauth/consent" style="display:flex;gap:.75rem;margin-top:1.5rem">
  <input type="hidden" name="token" value="${escapeHtml(token)}">
  <button name="decision" value="approve" type="submit" style="font-size:1rem;padding:.5rem 1rem">Approve ${origin}</button>
  <button name="decision" value="deny" type="submit" style="font-size:1rem;padding:.5rem 1rem">Deny</button>
</form>
</body>`);
}

// POST /api/oauth/consent — the user's decision on the interstitial above.
// Approving remembers the origin for this user (silent thereafter); denying
// bounces back with access_denied. Re-checks the SSO cookie so only the very
// identity the interstitial named can approve.
export async function handleConsent(req: Request, env: Env): Promise<Response> {
  const form = new URLSearchParams(await req.text());
  const token = (form.get("token") || "").trim();
  const decision = form.get("decision");
  if (!token) return badRequest("missing consent token");
  const raw = await env.KNOWN_KV.get(`oauth-consent-req:${token}`);
  if (!raw) return badRequest("consent request expired — start sign-in again");
  await env.KNOWN_KV.delete(`oauth-consent-req:${token}`); // single-use
  const r: ConsentReq = JSON.parse(raw);

  const subject = await readSsoSubject(req, env);
  if (!subject || subject !== r.subject) return badRequest("sign-in session changed — start again");

  if (decision !== "approve") {
    const err = new URL(r.redirect_uri);
    err.searchParams.set("error", "access_denied");
    if (r.state) err.searchParams.set("state", r.state);
    return Response.redirect(err.toString(), 302);
  }
  const target = new URL(r.redirect_uri).origin;
  await env.KNOWN_KV.put(`oauth-consent:${subject}:${target}`, "1", { expirationTtl: 90 * 24 * 60 * 60 });
  const code = await mintAuthCode(subject, { redirect_uri: r.redirect_uri, code_challenge: r.code_challenge, code_challenge_method: "S256" }, env);
  return Response.redirect(clientRedirect(r.redirect_uri, code, r.state), 302);
}

function json(status: number, data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function html(status: number, text: string): Response {
  return new Response(text, { status, headers: { "Content-Type": "text/plain; charset=utf-8" } });
}

function badRequest(msg: string): Response {
  return html(400, `Bad request: ${msg}`);
}

function oauthError(status: number, error: string, description: string): Response {
  return json(status, { error, error_description: description });
}
