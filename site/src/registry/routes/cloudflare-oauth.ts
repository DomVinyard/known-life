import type { Env } from "../lib/types";
import { verifyToken } from "../lib/jwt";
import { checkRate } from "../lib/ratelimit";
import {
  cfOAuthConfigured,
  cfCallbackUrl,
  buildAuthorizeUrl,
  exchangeCode,
  listAccounts,
  encryptSecret,
  putGrant,
  genVerifier,
  s256,
  randomToken,
  type CfGrant,
} from "../lib/cf-oauth";

/**
 * Cloudflare OAuth — the consent flow that replaces the cf-drop token paste.
 *
 *   POST /api/setup/cf-oauth/start   (Bearer known.life JWT)
 *     The agent calls this. We mint a PKCE verifier + opaque `state` bound to the
 *     caller's github:<login>, stash them in KV, and return the dash.cloudflare.com
 *     consent URL. The agent shows the URL to the user — one tap, no paste.
 *
 *   GET  /oauth/cf/callback          (the user's browser lands here post-consent)
 *     Validate `state`, exchange `code` at /oauth2/token (confidential client +
 *     PKCE verifier), record which account(s) the grant can see, and persist the
 *     REFRESH token (encrypted) under the user at central. The access token is
 *     never stored — it's minted on demand by lib/cf-oauth mintAccessToken.
 *
 * The CF credential never reaches the agent transcript or the container: it lives
 * only in this worker (KV, encrypted) and is brokered. Mirrors the cf-drop auth
 * model (JWT-bound at creation) but eliminates the paste.
 */

const STATE_TTL_S = 600; // 10 min — user has to click through the CF consent

interface PendingCfOAuth {
  login: string;
  code_verifier: string;
}

// POST /api/setup/cf-oauth/start
export async function handleCfOAuthStart(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rl = await checkRate(env, `cf-oauth-start:${ip}`, 20, 60 * 60);
  if (!rl.ok) return json(429, { error: "rate_limited", retry_after_s: rl.retryAfter });

  if (!cfOAuthConfigured(env)) {
    return json(503, { error: "not_configured", hint: "CF_OAUTH_CLIENT_ID/SECRET unset on the worker" });
  }

  const authHeader = req.headers.get("Authorization") ?? "";
  const tok = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  const subject = tok ? await verifyToken(tok, env) : null;
  if (!subject || !subject.startsWith("github:")) return json(401, { error: "unauthorized" });
  const login = subject.slice("github:".length);

  const verifier = genVerifier();
  const challenge = await s256(verifier);
  const state = randomToken(24);
  const pending: PendingCfOAuth = { login, code_verifier: verifier };
  await env.KNOWN_KV.put(`cf-oauth:pending:${state}`, JSON.stringify(pending), { expirationTtl: STATE_TTL_S });

  const authorize_url = buildAuthorizeUrl(env, {
    state,
    codeChallenge: challenge,
    redirectUri: cfCallbackUrl(env),
  });
  return json(200, { ok: true, authorize_url, state, expires_in: STATE_TTL_S });
}

// GET /oauth/cf/callback?code=&state=
export async function handleCfOAuthCallback(req: Request, env: Env): Promise<Response> {
  if (!cfOAuthConfigured(env)) return htmlResp(503, page("Not configured", "This known.life deploy has no Cloudflare OAuth client set."));

  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const oauthErr = url.searchParams.get("error");
  if (oauthErr) return htmlResp(400, page("Cancelled", `Cloudflare returned "${escapeHtml(oauthErr)}". Re-run setup in your agent to try again.`));
  if (!code || !state) return htmlResp(400, page("Bad request", "Missing code/state from Cloudflare."));

  const raw = await env.KNOWN_KV.get(`cf-oauth:pending:${state}`);
  if (!raw) return htmlResp(410, page("Expired", "This link expired or was already used. Re-run setup in your agent for a fresh one."));
  await env.KNOWN_KV.delete(`cf-oauth:pending:${state}`); // single-use
  const pending: PendingCfOAuth = JSON.parse(raw);

  let tok;
  try {
    tok = await exchangeCode(env, { code, codeVerifier: pending.code_verifier, redirectUri: cfCallbackUrl(env) });
  } catch (e) {
    return htmlResp(502, page("Couldn't connect", `Token exchange with Cloudflare failed: ${escapeHtml(String((e as Error).message))}`));
  }
  if (!tok.refresh_token) {
    return htmlResp(502, page("Couldn't connect", "Cloudflare returned no refresh token (the offline_access scope is required)."));
  }

  // Record which account(s) the grant can reach — the deploy target.
  const accounts = await listAccounts(tok.access_token);
  const primary = accounts.length > 0 ? accounts[0] : null;

  const grant: CfGrant = {
    refresh_token_enc: await encryptSecret(env, tok.refresh_token),
    account_id: primary?.id ?? null,
    account_name: primary?.name ?? null,
    accounts,
    updated_at: Date.now(),
  };
  await putGrant(env, pending.login, grant);

  const acctNote =
    accounts.length === 0
      ? "No Cloudflare account was visible to the grant — you may need to re-consent with an account selected."
      : accounts.length === 1
        ? `Connected account: ${escapeHtml(primary!.name)}.`
        : `Connected ${accounts.length} accounts; deploys will target ${escapeHtml(primary!.name)}.`;

  return htmlResp(200, page("Connected", `Cloudflare is connected for @${escapeHtml(pending.login)}. ${acctNote} Return to your agent — it has everything it needs. You can close this tab.`));
}

// --- helpers ---

function json(status: number, data: unknown): Response {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8" } });
}

function htmlResp(status: number, body: string): Response {
  return new Response(body, { status, headers: { "Content-Type": "text/html; charset=utf-8" } });
}

function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} — known.life</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         max-width: 32rem; margin: 4rem auto 2rem; padding: 0 1.25rem; }
  h1 { font-size: 1.25rem; margin: 0 0 .5rem; }
  p { color: #333; } @media (prefers-color-scheme: dark) { p { color: #ccc; } }
</style></head><body><h1>${escapeHtml(title)}</h1><p>${body}</p></body></html>`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string));
}
