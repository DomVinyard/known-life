import type { Env } from "../lib/types";
import { verifyToken } from "../lib/jwt";
import { checkRate } from "../lib/ratelimit";

/**
 * /setup — cold-start credential delivery for the agent-driven setup flow.
 *
 * Onboarding is agent-driven (the user never operates a terminal): the agent
 * device-flows into a known.life JWT (sub: github:<login>) via routes/mcp-oauth,
 * and the OAuth bridge caches the GitHub access token at gh:tok:<login> as a
 * side-effect of the elevated-scope grant. Cloudflare is captured once via OAuth
 * consent and brokered (routes/cloudflare-oauth: start → status → token).
 *
 * This module is now just the GitHub-token delivery endpoint — the non-CF half
 * of the retired `redeem`. (The old cf-drop browser token-paste + redeem flow,
 * and the pre-Life hosted /setup curl-handoff before it, were removed once the
 * Cloudflare OAuth broker shipped: setup@2.25.x calls cf-oauth, not cf-drop.)
 */

function json(status: number, data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

// POST /api/setup/github-token  (Bearer known.life JWT)
//
// Hands the device-flow-cached GitHub token (gh:tok:<login>) back to the
// JWT-bound setup process so it can create the repo (POST /user/repos) and
// register the lifekey (POST /user/keys). The token is returned only to a caller
// proving the owner's known.life JWT, never baked into a fetchable artifact.
export async function handleSetupGithubToken(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  const rl = await checkRate(env, `setup-gh-token:${ip}`, 60, 60 * 60);
  if (!rl.ok) return json(429, { error: "rate_limited", retry_after_s: rl.retryAfter });

  const authHeader = req.headers.get("Authorization") ?? "";
  const tok = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  const subject = tok ? await verifyToken(tok, env) : null;
  if (!subject || !subject.startsWith("github:")) return json(401, { error: "unauthorized" });
  const login = subject.slice("github:".length);

  // gh:tok has a 1h TTL on the OAuth bridge. 410 distinguishes "your JWT is fine
  // but the upstream GitHub credential it represents has expired" from a 401 —
  // the setup state machine restarts the device flow on 410. The key is
  // lowercased: GitHub logins are case-insensitive (see cf-oauth GRANT_KEY).
  const ghRaw = await env.KNOWN_KV.get(`gh:tok:${login.toLowerCase()}`);
  if (!ghRaw) return json(410, { error: "gh_token_expired", hint: "OAuth cache expired; restart device flow" });
  const gh = JSON.parse(ghRaw) as { token: string; scope: string };

  return json(200, { ok: true, github_login: login, github_token: gh.token, scope: gh.scope });
}
