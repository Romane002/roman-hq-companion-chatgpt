// The check of OpenAI's ID token after sign-in (SPEC v1.13 INT-10 (b); ROADMAP M10, L10.2; D-243), as OpenAI's
// "Registration and sign-in" page asks (developers.openai.com/siwc, read 2026-11-08): the signature against OpenAI's
// published keys (its JWKS), the issuer, the audience against the issued client id, the expiry with a few seconds'
// tolerance, the nonce saved for this attempt, a subject, and a session id that is not empty when present. Node's own
// crypto does the signature (RS256 or ES256); a key id not yet known fetches the keys once more. Part of the
// companion's open-source part: Node's own parts only.
import { createPublicKey, verify, type JsonWebKey } from "node:crypto";

export interface IdClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nonce?: string;
  email?: string;
  sid?: string;
  [claim: string]: unknown;
}

export type IdCheck = { ok: true; claims: IdClaims } | { ok: false; why: string };

// The keys, fetched again when asked for `fresh` (an unknown key id).
export type Keys = (fresh: boolean) => Promise<JsonWebKey[]>;

const TOLERANCE_SECONDS = 5;

const fromBase64url = (part: string): Buffer => Buffer.from(part, "base64url");
const json = (part: string): unknown => JSON.parse(fromBase64url(part).toString("utf8"));
const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

export async function verifyIdToken(token: string, keys: Keys, expected: { issuer: string; clientId: string; nonce: string; nowSeconds: number }): Promise<IdCheck> {
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false, why: "not a token" };
  const [head, body, signature] = parts as [string, string, string];
  let header: unknown;
  let claims: unknown;
  try {
    header = json(head);
    claims = json(body);
  } catch {
    return { ok: false, why: "not a token" };
  }
  if (!isObject(header) || !isObject(claims)) return { ok: false, why: "not a token" };
  const alg = header.alg;
  if (alg !== "RS256" && alg !== "ES256") return { ok: false, why: "an algorithm this check does not take" };
  const kid = typeof header.kid === "string" ? header.kid : null;
  let key = (await keys(false)).find((each) => (kid === null || each.kid === kid) && (each.alg === undefined || each.alg === alg));
  if (!key) key = (await keys(true)).find((each) => (kid === null || each.kid === kid) && (each.alg === undefined || each.alg === alg));
  if (!key) return { ok: false, why: "no published key for it" };
  let good = false;
  try {
    const publicKey = createPublicKey({ key, format: "jwk" });
    const data = Buffer.from(`${head}.${body}`);
    good = alg === "RS256" ? verify("sha256", data, publicKey, fromBase64url(signature)) : verify("sha256", data, { key: publicKey, dsaEncoding: "ieee-p1363" }, fromBase64url(signature));
  } catch {
    good = false;
  }
  if (!good) return { ok: false, why: "a signature that does not match" };
  const c = claims as Record<string, unknown>;
  if (c.iss !== expected.issuer) return { ok: false, why: "another issuer" };
  const audience = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!audience.includes(expected.clientId)) return { ok: false, why: "another audience" };
  if (typeof c.exp !== "number" || c.exp + TOLERANCE_SECONDS < expected.nowSeconds) return { ok: false, why: "expired" };
  if (typeof c.iat !== "number") return { ok: false, why: "no issue time" };
  if (c.nonce !== expected.nonce) return { ok: false, why: "another nonce" };
  if (typeof c.sub !== "string" || !c.sub) return { ok: false, why: "no subject" };
  if (c.sid !== undefined && (typeof c.sid !== "string" || !c.sid.trim())) return { ok: false, why: "an empty session id" };
  return { ok: true, claims: c as IdClaims };
}
