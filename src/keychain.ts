// The companion's secrets in the Mac's Keychain (SPEC v1.13 INT-10 (a), (b); ROADMAP M10, L10.2; D-246): its key from
// HQ, the owner's ChatGPT sign-in and this Mac's host id, each a generic password under one service, kept by macOS's
// own `security` tool and never in a plain file. A secret never travels on a command line, where another program on
// the Mac could read it: it is written through `security -i`, which takes its command on standard input, as hex
// (`-X`), and read back with `find-generic-password -w`. The value is kept as base64, so what comes back is plain ASCII.
// `security -i` reads one line of at most 4,096 characters (MAX_LINE_LEN in Apple's SecurityTool/macOS/security.c,
// read 2026-11-08), and a ChatGPT sign-in's tokens are longer than that once written as hex: so a long value is kept
// in pieces of 1,500 characters, each its own item, under a first item that names how many there are and the whole
// value's SHA-256. New pieces are written beside the old ones (two sets, "a" and "b"), the first item is changed last
// and the old pieces removed after, so a stop half-way leaves the value as it was; a piece missing or changed reads as
// no value at all. Part of the companion's open-source part: Node's own parts only. Tests hand it a stand-in for
// `security`.
import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";

export interface SecretStore {
  get(name: string): Promise<string | null>;
  set(name: string, value: string): Promise<void>;
  remove(name: string): Promise<void>;
}

export type Run = (args: string[], input?: string) => Promise<{ code: number; stdout: string }>;

// The exit status `security` gives for an item that is not there (errSecItemNotFound).
const NOT_FOUND = 44;
const SECURITY = "/usr/bin/security";

export const runSecurity: Run = (args, input) =>
  new Promise((resolve) => {
    if (input === undefined) {
      execFile(SECURITY, args, { encoding: "utf8" }, (error, stdout) => {
        // On a non-zero exit, the error's code is the exit status; a tool that is not there gives a word instead.
        const status = (error as { code?: unknown } | null)?.code;
        resolve({ code: !error ? 0 : typeof status === "number" ? status : 1, stdout: stdout ?? "" });
      });
      return;
    }
    const child = spawn(SECURITY, args, { stdio: ["pipe", "pipe", "ignore"] });
    let stdout = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => (stdout += chunk));
    child.on("close", (code) => resolve({ code: code ?? 1, stdout }));
    child.on("error", () => resolve({ code: 1, stdout }));
    child.stdin.end(input);
  });

// A name or service as `security -i` reads a word: plain letters, digits, dashes, dots and spaces only, quoted.
function word(value: string): string {
  if (!/^[A-Za-z0-9 ._-]+$/.test(value)) throw new Error("keychain: a name with characters it does not take");
  return `"${value}"`;
}

// The longest piece kept in one item, and the longest line `security -i` is given (its limit is 4,096 with the
// line's end and its last character).
export const PIECE = 1_500;
export const LINE_MOST = 4_000;
const PIECES = /^pieces:([ab]):(\d{1,3}):([0-9a-f]{64})$/;
const sha256 = (text: string) => createHash("sha256").update(text).digest("hex");

export function keychain(service: string, run: Run = runSecurity): SecretStore {
  // One item's text as kept: base64, or the first item's "pieces:<set>:<how many>:<SHA-256>".
  const readItem = async (name: string): Promise<string | null> => {
    const found = await run(["find-generic-password", "-s", service, "-a", name, "-w"]);
    if (found.code === NOT_FOUND) return null;
    if (found.code !== 0) throw new Error(`keychain: reading "${name}" failed (${found.code})`);
    return found.stdout.trim();
  };
  const writeItem = async (name: string, text: string): Promise<void> => {
    const line = `add-generic-password -U -s ${word(service)} -a ${word(name)} -X ${Buffer.from(text, "utf8").toString("hex")}\n`;
    if (line.length > LINE_MOST) throw new Error(`keychain: "${name}" is too long for one line`);
    const done = await run(["-i"], line);
    if (done.code !== 0) throw new Error(`keychain: keeping "${name}" failed (${done.code})`);
  };
  const removeItem = async (name: string): Promise<void> => {
    const done = await run(["delete-generic-password", "-s", service, "-a", name]);
    if (done.code !== 0 && done.code !== NOT_FOUND) throw new Error(`keychain: removing "${name}" failed (${done.code})`);
  };
  // The pieces the first item names now: their set and how many.
  const piecesOf = (top: string | null): { set: "a" | "b"; count: number } | null => {
    const match = top === null ? null : PIECES.exec(top);
    return match ? { set: match[1] as "a" | "b", count: Number(match[2]) } : null;
  };

  return {
    async get(name) {
      word(name);
      const top = await readItem(name);
      if (top === null) return null;
      const match = PIECES.exec(top);
      if (!match) return Buffer.from(top, "base64").toString("utf8");
      let text = "";
      for (let i = 0; i < Number(match[2]); i++) {
        const piece = await readItem(`${name}.${match[1]}.${i}`);
        if (piece === null) return null;
        text += piece;
      }
      return sha256(text) === match[3] ? Buffer.from(text, "base64").toString("utf8") : null;
    },
    async set(name, value) {
      word(name);
      const text = Buffer.from(value, "utf8").toString("base64");
      const before = piecesOf(await readItem(name));
      if (text.length <= PIECE) {
        await writeItem(name, text);
      } else {
        const set = before?.set === "a" ? "b" : "a";
        const count = Math.ceil(text.length / PIECE);
        for (let i = 0; i < count; i++) await writeItem(`${name}.${set}.${i}`, text.slice(i * PIECE, (i + 1) * PIECE));
        await writeItem(name, `pieces:${set}:${count}:${sha256(text)}`);
      }
      if (before) for (let i = 0; i < before.count; i++) await removeItem(`${name}.${before.set}.${i}`);
    },
    async remove(name) {
      word(name);
      const before = piecesOf(await readItem(name));
      await removeItem(name);
      if (before) for (let i = 0; i < before.count; i++) await removeItem(`${name}.${before.set}.${i}`);
    },
  };
}

// The same, in memory, for the tests and for a machine that is not a Mac.
export function memoryStore(): SecretStore & { items: Map<string, string> } {
  const items = new Map<string, string>();
  return {
    items,
    get: async (name) => items.get(name) ?? null,
    set: async (name, value) => void items.set(name, value),
    remove: async (name) => void items.delete(name),
  };
}
