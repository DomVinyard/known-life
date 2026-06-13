import type { Env } from "../lib/types";
import { getVersion, getPackage, bumpInstall, providersOf } from "../lib/db";
import { getBlob } from "../lib/blobs";
import { checkRate } from "../lib/ratelimit";

/**
 * GET /api/provides/:cap — reverse capability lookup.
 *
 * Returns the gene(s) whose latest version provides `:cap`, ranked by
 * installs. The engine uses this to resolve an unmet `requires: <cap>` to the
 * REAL provider gene, instead of guessing the gene name from the cap's
 * namespace (which breaks when they differ — e.g. `identity.lifekey` →
 * `lifekey`, not `identity`).
 */
export async function handleProvides(env: Env, cap: string): Promise<Response> {
  const providers = await providersOf(env, cap);
  return new Response(JSON.stringify({ cap, providers }), {
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

/**
 * GET /api/resolve/:name/:version — the engine install endpoint.
 *
 * Returns a gene version as a manifest plus inlined file blobs, so the Life
 * engine's known.life resolver can write `.genome/<name>/` and pin
 * `name@version` + content_hash in `.life.lock`. `:version` may be `latest`.
 *
 * Counts an install (deferred) so rankings reflect real engine pulls, not just
 * browser/curl page views.
 */
export async function handleResolve(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  name: string,
  versionArg: string,
): Promise<Response> {
  // Only a real install counts toward rankings. The engine's install path passes
  // ?reason=install; `fetch` (editing) and `fresh` (staleness) deliberately don't.
  // But an install/sync resolve counts only when it's a GENUINE adoption — the
  // engine sends `have=<version this .life already has pinned>`, and we bump the
  // counter only when the version we serve differs from it (or there's no prior,
  // so `have` is absent). This is what stops every ephemeral cold boot — which
  // re-resolves the same floating defaults each session — from inflating the
  // count: a steady-state re-sync sends `have` equal to what it resolves to and
  // is not counted; a first install or a moved float still is.
  const reqUrl = new URL(req.url);
  const isInstall = reqUrl.searchParams.get("reason") === "install";
  const have = reqUrl.searchParams.get("have");
  const life = reqUrl.searchParams.get("life");
  const pkg = await getPackage(env, name);
  if (!pkg) {
    // Common agent misfire: someone said "install known.life" and the agent
    // treated it as a gene name. known.life is the registry, not a gene.
    // Signpost the runbook so the agent can recover without searching.
    const normalised = name.toLowerCase().replace(/^known\.life\/?/, "").replace(/^\/+/, "");
    if (normalised === "" || name.toLowerCase() === "known.life" || name.toLowerCase() === "life-setup") {
      return json(404, {
        error: "not_a_gene",
        name,
        hint: "known.life is the registry, not a gene. To set up a fresh repo, follow https://known.life/install.txt (or https://known.life/llms.txt). The cold-start one-liner is: curl -fsSL https://known.life/install.sh | sh",
        runbook: "https://known.life/install.txt",
        llms: "https://known.life/llms.txt",
      });
    }
    return json(404, { error: "no_such_package", name });
  }

  const version = versionArg === "latest" ? pkg.latest_version : versionArg;
  if (!version) return json(404, { error: "no_version", name });

  const v = await getVersion(env, name, version);
  if (!v) return json(404, { error: "no_such_version", name, version });
  if (v.yanked) {
    // Still resolvable (reproducibility) but loudly flagged.
    // The engine surfaces this as a warning on install.
  }

  const manifest = JSON.parse(v.manifest_json) as Record<string, string>;
  const files: Record<string, string> = {};
  for (const [path, sha] of Object.entries(manifest)) {
    const content = await getBlob(env, sha);
    if (content === null) return json(500, { error: "missing_blob", path, sha });
    files[path] = content;
  }

  // Count a genuine adoption, but cap per-IP so a forged ?life=&reason=install
  // spray can't inflate the ranking signal. The check + bump run off the
  // response path (waitUntil) since the count is advisory, not load-bearing.
  if (isInstall && have !== version) {
    const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
    ctx.waitUntil(
      checkRate(env, `install-bump:${ip}`, 60, 3600).then((rl) => {
        if (rl.ok) return bumpInstall(env, name, version, life);
      }),
    );
  }

  return json(200, {
    name,
    version,
    content_hash: v.content_hash,
    yanked: !!v.yanked,
    yanked_reason: v.yanked_reason ?? null,
    verified_state: pkg.verified_state,
    requires: JSON.parse(v.requires_json ?? "[]"),
    provides: JSON.parse(v.provides_json ?? "[]"),
    inputs: JSON.parse(v.inputs_json ?? "[]"),
    files,
  });
}

function json(status: number, data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}
