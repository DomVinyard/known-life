import { describe, it, expect, beforeEach } from "vitest";
import { deprecateVersion, getVersion, highestVersion } from "../src/registry/lib/db";
import { MockD1 } from "./d1-mock";

// The yank reason is the agent-legible half of deprecation: stored with the
// version forever, served on resolve, and carried by the MVS flip's
// yank-on-new-selection error (bzlmod's
// error-with-reason model). These tests pin the round-trip over the REAL
// schema.sql — including the yanked_reason migration ALTER, which the d1-mock
// now applies with the production adapter's duplicate-skip contract.

const env = (db: MockD1) => ({ DB: db }) as any;

let db: MockD1;
beforeEach(async () => {
  db = new MockD1();
  // the FK chain: accounts ← names ← packages ← versions
  await db.prepare(
    "INSERT INTO accounts (id, email, created_at) VALUES ('acct', 'a@b.c', 1)",
  ).bind().run();
  await db.prepare(
    "INSERT INTO names (name, owner_account, created_at) VALUES ('demo', 'acct', 1)",
  ).bind().run();
  await db.prepare(
    "INSERT INTO packages (name, owner_account, latest_version, install_count, verified_state, created_at, updated_at) " +
    "VALUES ('demo', 'acct', '1.1.0', 0, 'scanned', 1, 1)",
  ).bind().run();
  for (const v of ["1.0.0", "1.1.0"]) {
    await db.prepare(
      "INSERT INTO versions (package, version, content_hash, manifest_json, published_at, yanked) " +
      "VALUES ('demo', ?, 'hash', '{}', 1, 0)",
    ).bind(v).run();
  }
});

describe("yank reason", () => {
  it("deprecation stores the reason; resolve-side reads serve it", async () => {
    await deprecateVersion(env(db), "demo", "1.1.0", "order-dependent test broke every consumer CI; use 1.1.1");
    const v = await getVersion(env(db), "demo", "1.1.0");
    expect(v?.yanked).toBe(1);
    expect(v?.yanked_reason).toContain("order-dependent test");
  });

  it("a reasonless deprecation stays null — never the string 'undefined'", async () => {
    await deprecateVersion(env(db), "demo", "1.0.0");
    const v = await getVersion(env(db), "demo", "1.0.0");
    expect(v?.yanked).toBe(1);
    expect(v?.yanked_reason).toBeNull();
  });

  it("latest falls back past the yanked version (existing contract intact)", async () => {
    await deprecateVersion(env(db), "demo", "1.1.0", "broken");
    expect(await highestVersion(env(db), "demo")).toBe("1.0.0");
  });
});
