// The companion's secrets in the Mac's Keychain (keychain.ts; SPEC v1.13 INT-10 (a); ROADMAP M10, L10.2; D-246), with a
// stand-in for macOS's `security` tool that keeps items as the real one does, answers 44 for one that is not there and,
// like the real one, cannot read a line of 4,096 characters or more in `-i` (MAX_LINE_LEN, Apple's security.c, read
// 2026-11-08): a secret round-trips, a long one in pieces that each fit a line, never travels on a command line, and
// names with characters `security -i` could misread are refused. The real Keychain is the owner's Mac's (DS-10.1).
import { describe, expect, test } from "vitest";
import { keychain, LINE_MOST, memoryStore, PIECE, type Run } from "./keychain.ts";

function standInSecurity() {
  const items = new Map<string, string>();
  const calls: { args: string[]; input?: string }[] = [];
  const run: Run = async (args, input) => {
    calls.push({ args, input });
    const flag = (list: string[], name: string) => list[list.indexOf(name) + 1] ?? "";
    if (args[0] === "find-generic-password") {
      const value = items.get(`${flag(args, "-s")}/${flag(args, "-a")}`);
      return value === undefined ? { code: 44, stdout: "" } : { code: 0, stdout: `${value}\n` };
    }
    if (args[0] === "delete-generic-password") return items.delete(`${flag(args, "-s")}/${flag(args, "-a")}`) ? { code: 0, stdout: "" } : { code: 44, stdout: "" };
    if (args[0] === "-i" && input) {
      if (input.length >= 4_096) return { code: 1, stdout: "" };
      const words = [...input.matchAll(/"([^"]*)"|(\S+)/g)].map((m) => m[1] ?? m[2] ?? "");
      if (words[0] !== "add-generic-password") return { code: 1, stdout: "" };
      items.set(`${flag(words, "-s")}/${flag(words, "-a")}`, Buffer.from(flag(words, "-X"), "hex").toString("utf8"));
      return { code: 0, stdout: "" };
    }
    return { code: 1, stdout: "" };
  };
  return { run, items, calls };
}

// The same, failing its nth write from now: a Mac that stops half-way through keeping a value.
function failingAt(security: ReturnType<typeof standInSecurity>, nth: number): Run {
  let writes = 0;
  return async (args, input) => (args[0] === "-i" && ++writes === nth ? { code: 1, stdout: "" } : security.run(args, input));
}

describe("the Keychain store", () => {
  test("keeps a secret and gives it back, the same words, unicode included", async () => {
    const security = standInSecurity();
    const store = keychain("Roman HQ companion", security.run);
    const secret = JSON.stringify({ access_token: "made-up-token", email: "made-up@example.com", note: "Tšau, ümber" });
    await store.set("chatgpt-credentials", secret);
    expect(await store.get("chatgpt-credentials")).toBe(secret);
    expect(await store.get("hq-key")).toBeNull();
    await store.remove("chatgpt-credentials");
    expect(await store.get("chatgpt-credentials")).toBeNull();
    await store.remove("chatgpt-credentials");
  });

  test("never puts a secret on a command line", async () => {
    const security = standInSecurity();
    const store = keychain("Roman HQ companion", security.run);
    await store.set("hq-key", "made-up-secret-value");
    for (const call of security.calls) expect(call.args.join(" ")).not.toContain("made-up-secret-value");
    const written = security.calls.filter((call) => call.args[0] === "-i");
    expect(written).toHaveLength(1);
    expect(written[0]?.input).not.toContain("made-up-secret-value");
  });

  test("a long value, as a ChatGPT sign-in's tokens are, is kept in pieces that each fit one line, and read back whole", async () => {
    const security = standInSecurity();
    const store = keychain("Roman HQ companion", security.run);
    const long = JSON.stringify({ id_token: "i".repeat(2_400), access_token: "a".repeat(2_600), refresh_token: "r".repeat(900), note: "Tšau" });
    await store.set("chatgpt", long);
    expect(await store.get("chatgpt")).toBe(long);
    const pieces = Math.ceil(Buffer.from(long, "utf8").toString("base64").length / PIECE);
    expect(pieces).toBe(6);
    const lines = security.calls.filter((call) => call.args[0] === "-i").map((call) => call.input ?? "");
    expect(lines.length, "six pieces and the first item").toBe(7);
    for (const line of lines) expect(line.length).toBeLessThanOrEqual(LINE_MOST);
    expect(lines.at(-1), "the first item is written last").toContain('-a "chatgpt" ');
    expect(security.items.get("Roman HQ companion/chatgpt")).toMatch(/^pieces:a:6:[0-9a-f]{64}$/);
    expect(security.items.get("Roman HQ companion/chatgpt.a.0")?.length).toBe(PIECE);

    // Kept again: the new pieces beside the old, the first item last, then the old pieces gone.
    const longer = long.replace("Tšau", "Tšau again");
    await store.set("chatgpt", longer);
    expect(await store.get("chatgpt")).toBe(longer);
    expect([...security.items.keys()].filter((key) => key.includes("chatgpt.")).sort()).toEqual(Array.from({ length: 6 }, (_, i) => `Roman HQ companion/chatgpt.b.${i}`));

    // A short value in its place leaves no piece behind; removing it removes everything.
    await store.set("chatgpt", "short");
    expect(await store.get("chatgpt")).toBe("short");
    expect([...security.items.keys()]).toEqual(["Roman HQ companion/chatgpt"]);
    await store.set("chatgpt", long);
    await store.remove("chatgpt");
    expect(security.items.size).toBe(0);
  });

  test("a stop half-way through keeping a new value leaves the one before as it was", async () => {
    const security = standInSecurity();
    const long = "y".repeat(4_000);
    await keychain("Roman HQ companion", security.run).set("chatgpt", long);
    await expect(keychain("Roman HQ companion", failingAt(security, 3)).set("chatgpt", "z".repeat(4_500))).rejects.toThrow('keeping "chatgpt.b.2" failed');
    expect(await keychain("Roman HQ companion", security.run).get("chatgpt")).toBe(long);
  });

  test("a piece missing or changed reads as no value, never as a wrong one", async () => {
    const security = standInSecurity();
    const store = keychain("Roman HQ companion", security.run);
    const long = "x".repeat(5_000);
    await store.set("chatgpt", long);
    const piece = security.items.get("Roman HQ companion/chatgpt.a.1")!;
    security.items.set("Roman HQ companion/chatgpt.a.1", piece.replace(/^./, "A"));
    expect(await store.get("chatgpt"), "changed").toBeNull();
    security.items.delete("Roman HQ companion/chatgpt.a.1");
    expect(await store.get("chatgpt"), "missing").toBeNull();
  });

  test("refuses a name `security -i` could misread", async () => {
    const store = keychain("Roman HQ companion", standInSecurity().run);
    await expect(store.set('a" -w "b', "x")).rejects.toThrow("characters it does not take");
  });

  test("the memory store behaves the same", async () => {
    const store = memoryStore();
    await store.set("host-id", "urn:uuid:made-up");
    expect(await store.get("host-id")).toBe("urn:uuid:made-up");
    await store.remove("host-id");
    expect(await store.get("host-id")).toBeNull();
  });
});
