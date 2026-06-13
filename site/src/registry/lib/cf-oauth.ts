import type { Env } from "./types";

/**
 * Cloudflare self-managed OAuth — the central half of paste-free infra onboarding.
 *
 * known.life holds ONE registered OAuth client (client_id 12eb82cb…, registered
 * 2026-06-13 — see the `cloudflare-oauth` knowledge plan + the `cloudflare` skill).
 * A user authorizes it once via a consent link; we exchange the code for an
 * access + refresh token, and keep the REFRESH token here at central (encrypted),
 * minting short-lived access tokens on demand. The container never holds a CF
 * credential — central brokers it. This is the CF twin of the GitHub-App verifier.
 *
 * Endpoints (verified live): authorize https://dash.cloudflare.com/oauth2/auth,
 * token https://dash.cloudflare.com/oauth2/token. Flow: auth-code + PKCE (S256).
 * The client is confidential (token_endpoint_auth_method client_secret_basic), so
 * the token leg authenticates with HTTP Basic client_id:client_secret AND the PKCE
 * verifier. Scopes are the create API's own snake_case vocabulary (NOT wrangler's
 * colon form) — the set the client was registered with is below.
 */

const CF_AUTHORIZE = "https://dash.cloudflare.com/oauth2/auth";
const CF_TOKEN = "https://dash.cloudflare.com/oauth2/token";
const CF_ACCOUNTS = "https://api.cloudflare.com/client/v4/accounts";

// The scopes known.life's client is registered with (least-privilege deploy set).
export const CF_OAUTH_SCOPES = [
  "account_read",
  "user_read",
  "workers_scripts_write",
  "workers_kv_storage_write",
  "workers_r2_write",
  "d1_write",
  "workers_routes_write",
  "offline_access", // yields the refresh token
];

export interface CfTokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
  scope?: string;
}

// The per-user grant we persist at central (KV `cf:grant:<login>`). The refresh
// token is encrypted at rest; the access token is NEVER stored (minted on demand).
export interface CfGrant {
  refresh_token_enc: string;
  account_id: string | null;
  account_name: string | null;
  accounts: Array<{ id: string; name: string }>;
  updated_at: number;
}

export function cfOAuthConfigured(env: Env): boolean {
  return Boolean(env.CF_OAUTH_CLIENT_ID && env.CF_OAUTH_CLIENT_SECRET);
}

export function cfCallbackUrl(env: Env): string {
  const origin = env.PUBLIC_URL ?? "https://known.life";
  return `${origin}/oauth/cf/callback`;
}

// --- PKCE + opaque tokens ---

export function randomToken(bytes = 32): string {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return Array.from(b, (n) => n.toString(16).padStart(2, "0")).join("");
}

// A PKCE code_verifier: 43–128 chars of unreserved set. 64 hex chars qualifies.
export function genVerifier(): string {
  return randomToken(32);
}

export async function s256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const b = String.fromCharCode(...new Uint8Array(digest));
  return btoa(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// --- authorize URL ---

export function buildAuthorizeUrl(
  env: Env,
  opts: { state: string; codeChallenge: string; redirectUri: string },
): string {
  const u = new URL(CF_AUTHORIZE);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", env.CF_OAUTH_CLIENT_ID!);
  u.searchParams.set("redirect_uri", opts.redirectUri);
  u.searchParams.set("scope", CF_OAUTH_SCOPES.join(" "));
  u.searchParams.set("state", opts.state);
  u.searchParams.set("code_challenge", opts.codeChallenge);
  u.searchParams.set("code_challenge_method", "S256");
  return u.toString();
}

// --- token leg (confidential client: HTTP Basic + PKCE verifier) ---

function basicAuth(env: Env): string {
  return "Basic " + btoa(`${env.CF_OAUTH_CLIENT_ID}:${env.CF_OAUTH_CLIENT_SECRET}`);
}

export async function exchangeCode(
  env: Env,
  opts: { code: string; codeVerifier: string; redirectUri: string },
): Promise<CfTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: opts.code,
    redirect_uri: opts.redirectUri,
    code_verifier: opts.codeVerifier,
  });
  return cfTokenRequest(env, body);
}

export async function refreshAccessToken(env: Env, refreshToken: string): Promise<CfTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  });
  return cfTokenRequest(env, body);
}

async function cfTokenRequest(env: Env, body: URLSearchParams): Promise<CfTokenResponse> {
  const res = await fetch(CF_TOKEN, {
    method: "POST",
    headers: {
      Authorization: basicAuth(env),
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body,
  });
  const j = (await res.json().catch(() => ({}))) as CfTokenResponse & { error?: string; error_description?: string };
  if (!res.ok || !j.access_token) {
    throw new Error(`cf token endpoint ${res.status}: ${j.error ?? "no_access_token"}${j.error_description ? ` (${j.error_description})` : ""}`);
  }
  return j;
}

// --- list accounts the granted token can see (to record the deploy target) ---

export async function listAccounts(accessToken: string): Promise<Array<{ id: string; name: string }>> {
  const res = await fetch(CF_ACCOUNTS, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
  });
  const j = (await res.json().catch(() => ({}))) as { success?: boolean; result?: Array<{ id: string; name: string }> };
  if (!res.ok || !j.success || !Array.isArray(j.result)) return [];
  return j.result.map((a) => ({ id: a.id, name: a.name }));
}

// --- encryption at rest (AES-GCM, key derived from JWT_SIGNING_KEY) ---
//
// The refresh token is long-lived and account-powerful; we never store it in the
// clear. The worker already holds a ≥32-byte JWT_SIGNING_KEY secret — derive an
// AES-256 key from it via SHA-256 so there is no second secret to manage.

async function aesKey(env: Env): Promise<CryptoKey> {
  const raw = env.JWT_SIGNING_KEY;
  if (!raw || raw.length < 32) {
    throw new Error("JWT_SIGNING_KEY missing/too short — refusing to encrypt CF refresh token");
  }
  const material = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`cf-oauth:${raw}`));
  return crypto.subtle.importKey("raw", material, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptSecret(env: Env, plaintext: string): Promise<string> {
  const key = await aesKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  return `${b64(iv)}.${b64(new Uint8Array(ct))}`;
}

export async function decryptSecret(env: Env, blob: string): Promise<string> {
  const key = await aesKey(env);
  const [ivB64, ctB64] = blob.split(".");
  if (!ivB64 || !ctB64) throw new Error("malformed encrypted blob");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(ivB64) }, key, unb64(ctB64));
  return new TextDecoder().decode(pt);
}

function b64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}
function unb64(s: string) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// --- per-user grant store (KV) ---

const GRANT_KEY = (login: string) => `cf:grant:${login}`;

export async function putGrant(env: Env, login: string, grant: CfGrant): Promise<void> {
  await env.KNOWN_KV.put(GRANT_KEY(login), JSON.stringify(grant));
}

export async function getGrant(env: Env, login: string): Promise<CfGrant | null> {
  const raw = await env.KNOWN_KV.get(GRANT_KEY(login));
  return raw ? (JSON.parse(raw) as CfGrant) : null;
}

// --- mint a fresh access token on demand (refresh + persist rotation) ---
//
// The broker entrypoint: given a github login with a stored grant, refresh the
// access token. Cloudflare rotates the refresh token, so re-encrypt + persist the
// new one. Returns null if the user has no grant (never connected, or revoked).

export async function mintAccessToken(
  env: Env,
  login: string,
): Promise<{ access_token: string; expires_in: number; account_id: string | null } | null> {
  const grant = await getGrant(env, login);
  if (!grant) return null;
  const refresh = await decryptSecret(env, grant.refresh_token_enc);
  const tok = await refreshAccessToken(env, refresh);
  if (tok.refresh_token && tok.refresh_token !== refresh) {
    grant.refresh_token_enc = await encryptSecret(env, tok.refresh_token);
    grant.updated_at = Date.now();
    await putGrant(env, login, grant);
  }
  return { access_token: tok.access_token, expires_in: tok.expires_in ?? 3600, account_id: grant.account_id };
}
