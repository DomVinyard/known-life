/**
 * The known.life genepool, as a request handler mounted inside the Astro site.
 *
 * This is the former standalone Worker's router lifted into this repo's
 * site so the docs site and the genepool are one deployable. Astro owns
 * `/`, `/docs/*`, and the static
 * assets; `src/middleware.ts` forwards the dynamic genepool paths here. The only
 * change from the original Worker `fetch` is that the `/` landing is gone — the
 * homepage is now the Astro page (which folds in a genepool overview).
 *
 *   GET  /healthz                  { ok }
 *   GET  /skill                    the known.life skill (markdown)
 *   GET|POST /mcp                  MCP server (JSON-RPC; public read surface)
 *   POST /api/claim                claim a name (Bearer/lifekey auth)
 *   POST /api/publish              the publish pipeline (auth → scan → fit → cut)
 *   POST /api/deprecate            deprecate a version (owner auth)
 *   POST /api/unpublish            hard-remove a recent version (owner auth)
 *   POST /api/wipe                 delete a name + all attached rows (admin auth)
 *   GET|POST /api/maintainers      list / grant / revoke account-level publish delegation (owner auth)
 *   GET  /api/resolve/:name/:ver   engine install endpoint (manifest + blobs)
 *   GET  /api/owner/:login        genes a GitHub login owns (public, JSON)
 *   GET  /explore                  ranked by installs
 *   GET  /search?q=                search
 *   GET  /:name                    gene page (content-negotiated)
 */
import type { Env } from "./lib/types";
import { handlePublish } from "./routes/publish";
import { handleResolve, handleProvides } from "./routes/resolve";
import { handleClaim } from "./routes/claim";
import { handleAuthChallenge, handleAuthProve } from "./routes/auth";
import { handleDeprecate, handleUnpublish, handleWipe } from "./routes/lifecycle";
import { handleMaintainers } from "./routes/maintainers";
import { handlePackage, handleExplore, handleSearch, handleOwner } from "./routes/package";
import { handleMcp } from "./routes/mcp";
import {
  handleProtectedResourceMetadata,
  handleAuthorizationServerMetadata,
  handleAuthorize,
  handleConsent,
  handleGithubCallback,
  handleDeviceCode,
  handleToken,
} from "./routes/mcp-oauth";
import {
  handleCreateSession,
  handleRedeemSession,
  handleCreateCfDrop,
  handleCfDropForm,
  handleCfDropSubmit,
  handleAgentRedeem,
} from "./routes/setup";
import {
  handleAppManifestStart,
  handleAppManifestCallback,
  handleExchangeVerify,
  handleExchangeDeleteBranch,
  handleAppInstalled,
} from "./routes/github-app";
import { handleSkill } from "./routes/skill";
import { isValidName } from "./lib/id";

// Minimal ExecutionContext shape — `waitUntil` is all the genepool uses (deferred
// install counting). The Astro Cloudflare adapter exposes it at locals.runtime.ctx.
export interface RegistryCtx {
  waitUntil(p: Promise<unknown>): void;
}

/**
 * Returns a Response for a genepool-owned path, or `null` if the path isn't a
 * genepool route — so the middleware can fall through to Astro. Keeping the
 * "not mine" signal explicit (null, not a 404 Response) is what lets a gene
 * page like `/laws` be tried only after Astro has declined the path.
 */
export async function registryFetch(
  req: Request,
  env: Env,
  ctx: RegistryCtx,
): Promise<Response | null> {
  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method;

  if (path === "/healthz") return json({ ok: true, ts: Date.now() });

  if (path === "/skill") return handleSkill(env);

  if (path === "/mcp") {
    if (method === "POST") return handleMcp(req, env);
    return new Response("known.life MCP server. POST JSON-RPC here. See known.life/skill.", {
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  // --- MCP OAuth bridge (RFC 6749 + PKCE, github.com upstream IdP) ---
  if (path === "/.well-known/oauth-protected-resource" && method === "GET")
    return handleProtectedResourceMetadata(req, env);
  if (path === "/.well-known/oauth-authorization-server" && method === "GET")
    return handleAuthorizationServerMetadata(req, env);
  if (path === "/api/oauth/authorize" && method === "GET") return handleAuthorize(req, env);
  if (path === "/api/oauth/consent" && method === "POST") return handleConsent(req, env);
  if (path === "/api/oauth/github-callback" && method === "GET") return handleGithubCallback(req, env);
  if (path === "/api/oauth/device-code" && method === "POST") return handleDeviceCode(req, env);
  if (path === "/api/oauth/token" && method === "POST") return handleToken(req, env);

  // --- /setup (hosted bootstrap flow; see routes/setup.ts) ---
  if (path === "/api/setup/session" && method === "POST") return handleCreateSession(req, env);
  const setupMatch = path.match(/^\/setup\/([a-f0-9]+)$/);
  if (setupMatch && method === "GET") return handleRedeemSession(req, env, setupMatch[1]);

  // --- durable verifier: the known.life GitHub App (central half) ---
  if (path === "/setup/github-app" && method === "GET") return handleAppManifestStart(req, env);
  if (path === "/setup/github-app/callback" && method === "GET") return handleAppManifestCallback(req, env);
  if (path === "/exchange/verify" && method === "POST") return handleExchangeVerify(req, env);
  if (path === "/exchange/delete-branch" && method === "POST") return handleExchangeDeleteBranch(req, env);
  if (path === "/exchange/installed" && method === "GET") return handleAppInstalled(req, env);

  // --- agent-driven setup: CF drop-box + redeem ---
  if (path === "/api/setup/cf-drop" && method === "POST") return handleCreateCfDrop(req, env);
  if (path === "/api/setup/redeem"  && method === "POST") return handleAgentRedeem(req, env);
  const cfDropMatch = path.match(/^\/setup\/cf\/([a-f0-9]+)$/);
  if (cfDropMatch && method === "GET")  return handleCfDropForm(req, env, cfDropMatch[1]);
  if (cfDropMatch && method === "POST") return handleCfDropSubmit(req, env, cfDropMatch[1]);

  // --- API ---
  if (path === "/api/auth/challenge" && method === "POST") return handleAuthChallenge(req, env);
  if (path === "/api/auth/prove" && method === "POST") return handleAuthProve(req, env);
  if (path === "/api/claim" && method === "POST") return handleClaim(req, env);
  if (path === "/api/publish" && method === "POST") return handlePublish(req, env);
  if (path === "/api/deprecate" && method === "POST") return handleDeprecate(req, env);
  if (path === "/api/unpublish" && method === "POST") return handleUnpublish(req, env);
  if (path === "/api/wipe" && method === "POST") return handleWipe(req, env);
  if (path === "/api/maintainers" && (method === "GET" || method === "POST")) return handleMaintainers(req, env);

  const resolveMatch = path.match(/^\/api\/resolve\/([a-z0-9.-]+)\/([a-z0-9.\-]+)$/);
  if (resolveMatch && method === "GET") {
    return handleResolve(req, env, ctx as ExecutionContext, resolveMatch[1], resolveMatch[2]);
  }

  const providesMatch = path.match(/^\/api\/provides\/([a-z0-9.\-]+)$/);
  if (providesMatch && method === "GET") return handleProvides(env, providesMatch[1]);

  const ownerMatch = path.match(/^\/api\/owner\/([A-Za-z0-9-]+)$/);
  if (ownerMatch && method === "GET") return handleOwner(env, ownerMatch[1]);

  // --- listings ---
  if (path === "/explore") return handleExplore(req, env);
  if (path === "/search") return handleSearch(req, env);

  // --- gene page: GET /:name (dotted names allowed). Only claim it when the
  // segment is a valid gene name; the middleware reaches here only after
  // Astro has 404'd, so real pages (/docs, …) never get this far. ---
  const nameMatch = path.match(/^\/([a-z0-9][a-z0-9.-]*)$/);
  if (nameMatch && method === "GET" && isValidName(nameMatch[1])) {
    return handlePackage(req, env, nameMatch[1]);
  }

  return null; // not a genepool route — let Astro handle it
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}
