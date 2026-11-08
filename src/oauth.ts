// Sign in with ChatGPT for the companion (SPEC v1.13 INT-10 (b); ROADMAP M10, L10.2; D-243, D-246), as OpenAI's pages
// for ChatGPT plan usage in open-source apps describe it (developers.openai.com/siwc, "Overview", "Registration and
// sign-in", "Accounts and sessions", "Errors and recovery", "Token reference", read 2026-11-08):
// - one host id for this Mac, `urn:uuid:<v4>`, chosen before the first sign-in and kept;
// - for each attempt a fresh state, nonce and PKCE verifier (S256), and a callback on 127.0.0.1 at `/auth/callback`
//   that takes one answer and closes (P-4, INT-10 (b));
// - the first sign-in registers this app with `client_id=dynamic_agent_client` and its name; the callback brings the
//   issued client id, which is kept and used for every later sign-in, never `dynamic_agent_client`;
// - the code is exchanged at OpenAI's token address with the PKCE verifier, no client secret; the ID token is checked
//   (jwt.ts); ChatGPT plan use is on only when the granted scopes hold `chatgpt.tokens.use.direct`;
// - the access token lasts an hour and is renewed with the refresh token near its end, one renewal at a time; a
//   refresh token OpenAI no longer takes clears the tokens and asks for a new sign-in; signing out revokes it first.
// OpenAI's addresses are read from its discovery document and must all be OpenAI's own. Part of the companion's
// open-source part: Node's own parts only; it is handed the function that sends a request and the one that opens
// the browser.
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { verifyIdToken, type Keys } from "./jwt.ts";
import type { Send } from "./responses.ts";

export const OPENAI_AUTH = "https://auth.openai.com";
export const DYNAMIC_CLIENT = "dynamic_agent_client";
export const AGENT_NAME = "Roman HQ companion";
export const SCOPES = ["openid", "profile", "email", "offline_access", "resource.invoke", "chatgpt.tokens.use.direct"] as const;
export const PLAN_SCOPE = "chatgpt.tokens.use.direct";
export const RESOURCE = "https://api.openai.com/v1";
export const CALLBACK_PATH = "/auth/callback";
export const PREFERRED_PORT = 1455;
// A renewal starts this long before the access token's hour ends.
const RENEW_BEFORE_MS = 120_000;
// The refresh codes after which the tokens are no use (OpenAI's "Refresh errors").
const UNUSABLE = new Set(["invalid_grant", "invalid_refresh_token", "token_expired", "refresh_token_expired", "refresh_token_invalidated", "refresh_token_reused"]);

export interface Endpoints {
  issuer: string;
  authorization: string;
  token: string;
  jwks: string;
  revocation: string | null;
}

// What a sign-in leaves, kept in the Mac's Keychain (keychain.ts) as OpenAI's page lays the record out.
export interface Credentials {
  issuer: string;
  subject: string;
  email: string | null;
  client_id: string;
  ext_agent_host_id: string;
  id_token: string;
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  scopes: string[];
  saved_at: string;
}

export const planAllowed = (credentials: Pick<Credentials, "scopes">): boolean => credentials.scopes.includes(PLAN_SCOPE);

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const random = (bytes: number) => randomBytes(bytes).toString("base64url");

export const newHostId = (): string => `urn:uuid:${randomUUID()}`;

export function pkce(): { verifier: string; challenge: string } {
  const verifier = random(32);
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

// OpenAI's discovery document; every address in it must be on the issuer's own origin.
export async function discover(send: Send, origin: string = OPENAI_AUTH): Promise<Endpoints> {
  const response = await send(`${origin}/.well-known/openid-configuration`, { method: "GET" });
  if (response.status !== 200) throw new Error(`sign-in: OpenAI's discovery answered ${response.status}`);
  const doc: unknown = await response.json();
  if (!isObject(doc) || doc.issuer !== origin) throw new Error("sign-in: the discovery names another issuer");
  const own = (value: unknown): string => {
    if (typeof value !== "string" || new URL(value).origin !== origin) throw new Error("sign-in: an address that is not OpenAI's own");
    return value;
  };
  return {
    issuer: origin,
    authorization: own(doc.authorization_endpoint),
    token: own(doc.token_endpoint),
    jwks: own(doc.jwks_uri),
    revocation: doc.revocation_endpoint === undefined ? null : own(doc.revocation_endpoint),
  };
}

export interface AuthorizeParams {
  clientId: string;
  hostId: string;
  redirectUri: string;
  state: string;
  nonce: string;
  challenge: string;
  idTokenHint?: string | null;
  loginHint?: string | null;
}

export function authorizeUrl(endpoints: Endpoints, params: AuthorizeParams): string {
  const url = new URL(endpoints.authorization);
  const q = url.searchParams;
  q.set("client_id", params.clientId);
  if (params.clientId === DYNAMIC_CLIENT) q.set("agent_name_hint", AGENT_NAME);
  q.set("ext_agent_host_id", params.hostId);
  if (params.idTokenHint) q.set("id_token_hint", params.idTokenHint);
  if (params.loginHint) q.set("login_hint", params.loginHint);
  q.set("response_type", "code");
  q.set("redirect_uri", params.redirectUri);
  q.set("scope", SCOPES.join(" "));
  q.set("resource", RESOURCE);
  q.set("state", params.state);
  q.set("nonce", params.nonce);
  q.set("code_challenge_method", "S256");
  q.set("code_challenge", params.challenge);
  return url.toString();
}

export interface Callback {
  redirectUri: string;
  // The first answer at the callback's path; the listener closes as soon as it has it, or at the timeout.
  answer: Promise<URLSearchParams | null>;
  close(): void;
}

const ANSWERED = (words: string) =>
  `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Roman HQ companion</title></head><body style="font:15px system-ui;margin:48px auto;max-width:420px"><p>${words}</p></body></html>`;

// The one-answer callback on 127.0.0.1 (P-4): the preferred port, or any free one when it is taken.
export async function listenOnce(port: number = PREFERRED_PORT, timeoutMs = 600_000): Promise<Callback> {
  let settle: (value: URLSearchParams | null) => void = () => undefined;
  const answer = new Promise<URLSearchParams | null>((resolve) => (settle = resolve));
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (req.method !== "GET" || url.pathname !== CALLBACK_PATH) {
      res.writeHead(404, { "content-type": "text/plain" });
      return res.end("");
    }
    const failed = url.searchParams.has("error");
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    res.end(ANSWERED(failed ? "The sign-in did not finish. You can close this window and try again from the companion's page." : "Signed in. You can close this window."));
    settle(url.searchParams);
    server.close();
  });
  const listen = (at: number) =>
    new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(at, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
  try {
    await listen(port);
  } catch {
    await listen(0);
  }
  const timer = setTimeout(() => {
    settle(null);
    server.close();
  }, timeoutMs);
  void answer.then(() => clearTimeout(timer));
  const redirectUri = `http://127.0.0.1:${(server.address() as AddressInfo).port}${CALLBACK_PATH}`;
  return {
    redirectUri,
    answer,
    close: () => {
      settle(null);
      server.close();
    },
  };
}

export interface TokenAnswer {
  access_token: string;
  refresh_token: string;
  id_token: string | null;
  token_type: string;
  expires_in: number;
  scope: string;
}
export type TokenResult = { ok: true; tokens: TokenAnswer } | { ok: false; status: number | null; code: string | null };

async function tokenPost(send: Send, endpoints: Endpoints, form: Record<string, string>): Promise<TokenResult> {
  let response: Response;
  try {
    response = await send(endpoints.token, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(form).toString() });
  } catch {
    return { ok: false, status: null, code: null };
  }
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (response.status !== 200 || !isObject(body)) return { ok: false, status: response.status, code: isObject(body) && typeof body.error === "string" ? body.error : null };
  if (typeof body.access_token !== "string" || typeof body.refresh_token !== "string") return { ok: false, status: 200, code: "incomplete" };
  return {
    ok: true,
    tokens: {
      access_token: body.access_token,
      refresh_token: body.refresh_token,
      id_token: typeof body.id_token === "string" ? body.id_token : null,
      token_type: typeof body.token_type === "string" ? body.token_type : "Bearer",
      expires_in: typeof body.expires_in === "number" ? body.expires_in : 3600,
      scope: typeof body.scope === "string" ? body.scope : "",
    },
  };
}

export const exchange = (send: Send, endpoints: Endpoints, p: { clientId: string; code: string; verifier: string; redirectUri: string }) =>
  tokenPost(send, endpoints, { grant_type: "authorization_code", client_id: p.clientId, code: p.code, code_verifier: p.verifier, redirect_uri: p.redirectUri, resource: RESOURCE });

export const renew = (send: Send, endpoints: Endpoints, p: { clientId: string; refreshToken: string }) =>
  tokenPost(send, endpoints, { grant_type: "refresh_token", client_id: p.clientId, refresh_token: p.refreshToken, resource: RESOURCE });

// Revoking the renewable session at sign-out; true when OpenAI confirmed it (an empty 200).
export async function revoke(send: Send, endpoints: Endpoints, p: { clientId: string; refreshToken: string }): Promise<boolean> {
  if (!endpoints.revocation) return false;
  try {
    const response = await send(endpoints.revocation, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: p.refreshToken, token_type_hint: "refresh_token", client_id: p.clientId }).toString() });
    return response.status === 200;
  } catch {
    return false;
  }
}

// OpenAI's published keys, kept between checks and fetched again on an unknown key id.
export function publishedKeys(send: Send, endpoints: Endpoints): Keys {
  let kept: import("node:crypto").JsonWebKey[] | null = null;
  return async (fresh) => {
    if (kept && !fresh) return kept;
    const response = await send(endpoints.jwks, { method: "GET" });
    const body: unknown = response.status === 200 ? await response.json() : null;
    kept = isObject(body) && Array.isArray(body.keys) ? (body.keys as import("node:crypto").JsonWebKey[]) : [];
    return kept;
  };
}

export type SignIn =
  | { kind: "signed_in"; credentials: Credentials }
  | { kind: "no_plan"; credentials: Credentials }
  | { kind: "declined" }
  | { kind: "failed"; why: string };

export interface SignInParts {
  send: Send;
  // Opens the system browser at the authorization address.
  open: (url: string) => Promise<void>;
  hostId: string;
  // The account's earlier sign-in on this Mac, if any: its issued client id and hints are reused.
  saved: Credentials | null;
  now: () => Date;
  origin?: string;
  port?: number;
  timeoutMs?: number;
}

export async function signIn(parts: SignInParts): Promise<SignIn> {
  let endpoints: Endpoints;
  try {
    endpoints = await discover(parts.send, parts.origin ?? OPENAI_AUTH);
  } catch (error) {
    return { kind: "failed", why: error instanceof Error ? error.message : "discovery" };
  }
  const state = random(32);
  const nonce = random(32);
  const { verifier, challenge } = pkce();
  const callback = await listenOnce(parts.port ?? PREFERRED_PORT, parts.timeoutMs);
  const clientId = parts.saved?.client_id ?? DYNAMIC_CLIENT;
  try {
    await parts.open(authorizeUrl(endpoints, { clientId, hostId: parts.hostId, redirectUri: callback.redirectUri, state, nonce, challenge, idTokenHint: parts.saved?.id_token ?? null, loginHint: parts.saved?.email ?? null }));
  } catch {
    callback.close();
    return { kind: "failed", why: "the browser did not open" };
  }
  const answer = await callback.answer;
  if (!answer) return { kind: "failed", why: "no answer from the browser" };
  if (answer.get("state") !== state) return { kind: "failed", why: "an answer for another sign-in" };
  const error = answer.get("error");
  if (error === "access_denied") return { kind: "declined" };
  if (error) return { kind: "failed", why: error };
  const code = answer.get("code");
  if (!code) return { kind: "failed", why: "no code" };
  const issued = answer.get("client_id");
  let useClient: string;
  if (clientId === DYNAMIC_CLIENT) {
    if (!issued || issued === DYNAMIC_CLIENT) return { kind: "failed", why: "the registration did not finish" };
    useClient = issued;
  } else {
    if (issued && issued !== clientId) return { kind: "failed", why: "an answer for another registration" };
    useClient = clientId;
  }
  const exchanged = await exchange(parts.send, endpoints, { clientId: useClient, code, verifier, redirectUri: callback.redirectUri });
  if (!exchanged.ok) return { kind: "failed", why: exchanged.code ?? `the token address answered ${exchanged.status ?? "nothing"}` };
  const tokens = exchanged.tokens;
  if (!tokens.id_token) return { kind: "failed", why: "no ID token" };
  const checked = await verifyIdToken(tokens.id_token, publishedKeys(parts.send, endpoints), { issuer: endpoints.issuer, clientId: useClient, nonce, nowSeconds: Math.floor(parts.now().getTime() / 1000) });
  if (!checked.ok) return { kind: "failed", why: `the ID token: ${checked.why}` };
  if (parts.saved && checked.claims.sub !== parts.saved.subject) return { kind: "failed", why: "another ChatGPT account" };
  const credentials: Credentials = {
    issuer: endpoints.issuer,
    subject: checked.claims.sub,
    email: typeof checked.claims.email === "string" ? checked.claims.email : null,
    client_id: useClient,
    ext_agent_host_id: parts.hostId,
    id_token: tokens.id_token,
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    token_type: tokens.token_type,
    expires_in: tokens.expires_in,
    scopes: tokens.scope.split(/\s+/).filter(Boolean),
    saved_at: parts.now().toISOString(),
  };
  return planAllowed(credentials) ? { kind: "signed_in", credentials } : { kind: "no_plan", credentials };
}

export interface CredentialKeeper {
  read(): Promise<Credentials | null>;
  write(credentials: Credentials): Promise<void>;
  // Drops the tokens and keeps the issued client id and the hints for the next sign-in.
  forgetTokens(): Promise<void>;
}

// A usable access token, renewed near its end and one renewal at a time; or why there is none: no sign-in (or one
// OpenAI no longer takes, whose tokens are then dropped), plan use not granted, or OpenAI not reached just now.
export type TokenNow = { token: string } | { failure: "signed_out" | "not_allowed" | "busy" };

export function accessTokens(send: Send, keeper: CredentialKeeper, now: () => Date, origin: string = OPENAI_AUTH): () => Promise<TokenNow> {
  let renewing: Promise<TokenNow> | null = null;
  let endpoints: Endpoints | null = null;
  return async () => {
    const credentials = await keeper.read();
    if (!credentials || !credentials.access_token || !credentials.refresh_token) return { failure: "signed_out" };
    if (!planAllowed(credentials)) return { failure: "not_allowed" };
    const ends = Date.parse(credentials.saved_at) + credentials.expires_in * 1000;
    if (now().getTime() < ends - RENEW_BEFORE_MS) return { token: credentials.access_token };
    if (renewing) return renewing;
    renewing = (async (): Promise<TokenNow> => {
      try {
        endpoints ??= await discover(send, origin);
        const renewed = await renew(send, endpoints, { clientId: credentials.client_id, refreshToken: credentials.refresh_token });
        if (!renewed.ok) {
          if (renewed.code && UNUSABLE.has(renewed.code)) {
            await keeper.forgetTokens();
            return { failure: "signed_out" };
          }
          return { failure: "busy" };
        }
        const tokens = renewed.tokens;
        await keeper.write({ ...credentials, access_token: tokens.access_token, refresh_token: tokens.refresh_token, id_token: tokens.id_token ?? credentials.id_token, token_type: tokens.token_type, expires_in: tokens.expires_in, scopes: tokens.scope ? tokens.scope.split(/\s+/).filter(Boolean) : credentials.scopes, saved_at: now().toISOString() });
        return { token: tokens.access_token };
      } catch {
        return { failure: "busy" };
      } finally {
        renewing = null;
      }
    })();
    return renewing;
  };
}
