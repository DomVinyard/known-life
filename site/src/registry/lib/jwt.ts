import { SignJWT, jwtVerify } from "jose";
import type { Env } from "./types";

// Gene-pool tokens are short-lived JWTs carrying a GitHub-identity subject
// (`github:<login>`), minted only after a lifekey signature proves the caller
// holds a key on github.com/<login>.keys (see routes/auth.ts). There is no other
// way to get one: identity is git identity, end of story.
//
// Issuer/audience are the deployment's own origin (env.PUBLIC_URL, set by the
// middleware), so the genepool is self-consistent wherever it runs — known.life
// or a self-host — with no hardcoded hostname to drift. Tokens live 1h, so
// there's nothing to migrate when the origin changes.

const TOKEN_TTL_SECONDS = 60 * 60; // 1 hour — re-auth is a cheap lifekey signature

async function getKey(env: Env): Promise<Uint8Array> {
  // Fail CLOSED: no in-repo fallback key. A fallback constant in a public repo
  // means any deploy that forgets to set JWT_SIGNING_KEY (a self-host, a
  // misconfigured redeploy) is silently forgeable — anyone knowing the constant
  // could mint a bearer for any github:<login>, incl. an admin. Refuse to
  // sign/verify without a real ≥32-byte key instead. verifyToken catches this
  // and returns null (→ 401), so a missing key locks the surface, never opens it.
  const raw = env.JWT_SIGNING_KEY;
  const bytes = raw ? new TextEncoder().encode(raw) : new Uint8Array(0);
  if (bytes.length < 32) {
    throw new Error("JWT_SIGNING_KEY missing or under 32 bytes — refusing to mint/verify tokens with a weak key");
  }
  return bytes.slice(0, 32);
}

function origin(env: Env): string {
  return env.PUBLIC_URL ?? "https://known.life";
}

// Mint a genepool token for a proven subject (`github:<login>`). The token IS
// the bearer credential for write endpoints until it expires.
export async function issueRegistryToken(subject: string, env: Env): Promise<string> {
  const key = await getKey(env);
  const iss = origin(env);
  return new SignJWT({})
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(iss)
    .setAudience(iss)
    .setSubject(subject)
    .setIssuedAt()
    .setExpirationTime(`${TOKEN_TTL_SECONDS}s`)
    .sign(key);
}

// Verify a genepool token and return its subject (`github:<login>`), or null.
export async function verifyToken(token: string, env: Env): Promise<string | null> {
  try {
    const key = await getKey(env);
    const iss = origin(env);
    const { payload } = await jwtVerify(token, key, { issuer: iss, audience: iss });
    // An SSO session cookie (kind:"sso", 30d) must NEVER be replayable as an API
    // bearer: the bearer is the kind-less 1h token from issueRegistryToken. Same
    // key/issuer/audience, so jwtVerify alone can't tell them apart — reject the
    // SSO kind explicitly here. (verifySsoSession is the mirror: it requires it.)
    if (payload.kind === "sso") return null;
    return typeof payload.sub === "string" ? payload.sub : null;
  } catch {
    return null;
  }
}

// --- SSO session (the `known_sso` cookie on this origin) ---
//
// The genepool is the SSO identity provider for every UI a .life deploys: a
// browser proves its GitHub identity ONCE (the OAuth → github.com round-trip),
// and we drop a long-lived `known_sso` cookie here. On every later /authorize —
// from any UI surface — we read this cookie and issue the auth code silently,
// no GitHub prompt. This token is distinct from the 1h bearer (`kind: "sso"`,
// 30d) so an SSO cookie can never be replayed as an API bearer.

const SSO_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days

export async function issueSsoSession(subject: string, env: Env): Promise<string> {
  const key = await getKey(env);
  const iss = origin(env);
  return new SignJWT({ kind: "sso" })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(iss)
    .setAudience(iss)
    .setSubject(subject)
    .setIssuedAt()
    .setExpirationTime(`${SSO_TTL_SECONDS}s`)
    .sign(key);
}

export async function verifySsoSession(token: string, env: Env): Promise<string | null> {
  try {
    const key = await getKey(env);
    const iss = origin(env);
    const { payload } = await jwtVerify(token, key, { issuer: iss, audience: iss });
    return payload.kind === "sso" && typeof payload.sub === "string" ? payload.sub : null;
  } catch {
    return null;
  }
}

export const SSO_COOKIE = "known_sso";
export const SSO_COOKIE_TTL_S = SSO_TTL_SECONDS;
