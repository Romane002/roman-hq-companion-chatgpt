// A stand-in for OpenAI's API, for the tests of the companion's ChatGPT part (SPEC v1.13 INT-10 (h); ROADMAP M10,
// L10.2; D-025, G-17): a small HTTP server on this machine that answers the two calls the companion makes,
// `GET /v1/models` and `POST /v1/responses`, in the shapes OpenAI's pages give (developers.openai.com/siwc, read
// 2026-11-08): a model list under `models`, and server-sent events for a response. A test sets the next reply: an
// answer streamed in pieces, a usage limit before the stream or in the middle of it, plan use not allowed, OpenAI
// unavailable, the sign-in not accepted, an incomplete response, a stream that ends without `response.completed`. It
// keeps every request, so a test can show what was sent: the instructions, the one input, `store: false`, and nothing
// else.
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

export type ChatgptReply =
  | { kind: "answer"; text: string }
  | { kind: "limit_before" }
  | { kind: "limit_midway" }
  | { kind: "not_eligible" }
  | { kind: "unavailable" }
  | { kind: "invalid_user" }
  | { kind: "admission"; status: number }
  | { kind: "incomplete" }
  | { kind: "cut_short" };

// How the stand-in's sign-in answers the next attempt: as a person who consents would, or with one thing wrong.
export type SignInCase =
  | "consent"
  | "decline"
  | "no_plan"
  | "no_issued_client"
  | "another_client"
  | "wrong_nonce"
  | "wrong_audience"
  | "expired"
  | "another_key"
  | "another_subject";

export interface ChatgptAsk {
  headers: IncomingMessage["headers"];
  body: Record<string, unknown>;
}

export interface ChatgptStandIn {
  url: string;
  asks: ChatgptAsk[];
  modelsAsked: number;
  // The token the stand-in accepts as the bearer; any other is answered 401 with OpenAI's invalid-user code.
  token: string;
  models: { slug: string; display_name: string; visibility: string }[];
  reply(reply: ChatgptReply): void;
  // OpenAI's sign-in side: each authorization asked, each token grant asked, each revocation.
  authorizations: URLSearchParams[];
  grants: URLSearchParams[];
  revoked: string[];
  signIn(how: SignInCase): void;
  // The next refresh is refused with OpenAI's code, as for a refresh token it no longer takes.
  refuseRefresh(code: string | null): void;
  // A made-up person's consent in a browser: asks the authorization address and follows its one redirect.
  browser(url: string): Promise<void>;
  stop(): Promise<void>;
}

export const ISSUED_CLIENT = "oaiapp_madeup_client";
export const SUBJECT = "made-up-subject";
const PLAN_SCOPES = "chatgpt.tokens.use.direct email offline_access openid profile resource.invoke";
const NO_PLAN_SCOPES = "email offline_access openid profile";

function jwt(key: KeyObject, kid: string, claims: Record<string, unknown>): string {
  const head = Buffer.from(JSON.stringify({ alg: "RS256", kid, typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return `${head}.${body}.${sign("sha256", Buffer.from(`${head}.${body}`), key).toString("base64url")}`;
}

const read = (req: IncomingMessage) =>
  new Promise<string>((resolve) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => resolve(body));
  });

const sse = (res: ServerResponse, events: Record<string, unknown>[]) => {
  res.writeHead(200, { "content-type": "text/event-stream", "x-request-id": "req_standin" });
  for (const event of events) res.write(`event: ${String(event.type)}\ndata: ${JSON.stringify(event)}\n\n`);
  res.end();
};

const deltas = (text: string) => {
  const pieces: Record<string, unknown>[] = [];
  for (let i = 0; i < text.length; i += 7) pieces.push({ type: "response.output_text.delta", delta: text.slice(i, i + 7) });
  return pieces;
};

export async function startChatgptStandIn(token: string): Promise<ChatgptStandIn> {
  let next: ChatgptReply = { kind: "answer", text: JSON.stringify({ summary: "A made-up summary.", takes: ["A made-up take."] }) };
  let signInCase: SignInCase = "consent";
  let refreshRefusal: string | null = null;
  const own = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const KID = "stand-in-key";
  const codes = new Map<string, { clientId: string; challenge: string; nonce: string; redirectUri: string }>();
  const refreshTokens = new Map<string, string>();
  const state: ChatgptStandIn = {
    url: "",
    asks: [],
    modelsAsked: 0,
    token,
    models: [
      { slug: "made-up-model", display_name: "Made-up model", visibility: "list" },
      { slug: "made-up-hidden", display_name: "Hidden", visibility: "hide" },
    ],
    reply: (reply) => {
      next = reply;
    },
    authorizations: [],
    grants: [],
    revoked: [],
    signIn: (how) => {
      signInCase = how;
    },
    refuseRefresh: (code) => {
      refreshRefusal = code;
    },
    browser: async (address) => {
      const asked = await fetch(address, { redirect: "manual" });
      const location = asked.headers.get("location");
      if (location) await fetch(location);
    },
    stop: async () => undefined,
  };
  const tokensFor = (clientId: string, nonce: string | null) => {
    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = { iss: state.url, sub: signInCase === "another_subject" ? "another-made-up-subject" : SUBJECT, aud: [signInCase === "wrong_audience" ? "oaiapp_another" : clientId], iat: now, exp: signInCase === "expired" ? now - 600 : now + 3600, email: "made-up@example.com", sid: "made-up-session" };
    if (nonce !== null) claims.nonce = signInCase === "wrong_nonce" ? "another-nonce" : nonce;
    const refresh = randomBytes(24).toString("base64url");
    refreshTokens.set(refresh, clientId);
    return { access_token: state.token, refresh_token: refresh, id_token: jwt(signInCase === "another_key" ? other.privateKey : own.privateKey, KID, claims), token_type: "Bearer", expires_in: 3600, scope: signInCase === "no_plan" ? NO_PLAN_SCOPES : PLAN_SCOPES, earliest_refresh_at: now + 60 };
  };
  const json = (res: ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { "content-type": "application/json", "x-request-id": "req_standin" });
    res.end(JSON.stringify(body));
  };

  const handle = async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const bearer = req.headers.authorization === `Bearer ${state.token}`;
    if (req.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
      return json(res, 200, { issuer: state.url, authorization_endpoint: `${state.url}/api/accounts/authorize`, token_endpoint: `${state.url}/api/accounts/oauth/token`, jwks_uri: `${state.url}/.well-known/jwks.json`, revocation_endpoint: `${state.url}/api/accounts/oauth/revoke` });
    }
    if (req.method === "GET" && url.pathname === "/.well-known/jwks.json") {
      return json(res, 200, { keys: [{ ...own.publicKey.export({ format: "jwk" }), kid: KID, alg: "RS256", use: "sig" }] });
    }
    if (req.method === "GET" && url.pathname === "/api/accounts/authorize") {
      const q = url.searchParams;
      state.authorizations.push(new URLSearchParams(q));
      const back = new URL(q.get("redirect_uri") ?? "http://127.0.0.1:1/");
      back.searchParams.set("state", q.get("state") ?? "");
      if (signInCase === "decline") {
        back.searchParams.set("error", "access_denied");
      } else {
        const asked = q.get("client_id") ?? "";
        const issued = asked === "dynamic_agent_client" ? ISSUED_CLIENT : asked;
        const code = randomBytes(16).toString("base64url");
        codes.set(code, { clientId: issued, challenge: q.get("code_challenge") ?? "", nonce: q.get("nonce") ?? "", redirectUri: q.get("redirect_uri") ?? "" });
        back.searchParams.set("code", code);
        back.searchParams.set("scope", signInCase === "no_plan" ? NO_PLAN_SCOPES.replace(/ /g, "+") : PLAN_SCOPES);
        if (signInCase === "another_client") back.searchParams.set("client_id", "oaiapp_another");
        else if (asked === "dynamic_agent_client" && signInCase !== "no_issued_client") back.searchParams.set("client_id", issued);
      }
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }
    if (req.method === "POST" && url.pathname === "/api/accounts/oauth/token") {
      const form = new URLSearchParams(await read(req));
      state.grants.push(form);
      if (form.get("resource") !== "https://api.openai.com/v1") return json(res, 400, { error: "invalid_target" });
      if (form.get("grant_type") === "authorization_code") {
        const asked = codes.get(form.get("code") ?? "");
        codes.delete(form.get("code") ?? "");
        const verifier = form.get("code_verifier") ?? "";
        if (!asked || asked.clientId !== form.get("client_id") || asked.redirectUri !== form.get("redirect_uri") || createHash("sha256").update(verifier).digest("base64url") !== asked.challenge) return json(res, 400, { error: "invalid_grant" });
        return json(res, 200, tokensFor(asked.clientId, asked.nonce));
      }
      if (form.get("grant_type") === "refresh_token") {
        if (refreshRefusal) return json(res, 400, { error: refreshRefusal });
        const known = refreshTokens.get(form.get("refresh_token") ?? "");
        if (!known || known !== form.get("client_id")) return json(res, 400, { error: "invalid_grant" });
        refreshTokens.delete(form.get("refresh_token") ?? "");
        const { id_token: _unused, ...rest } = tokensFor(known, null);
        return json(res, 200, rest);
      }
      return json(res, 400, { error: "unsupported_grant_type" });
    }
    if (req.method === "POST" && url.pathname === "/api/accounts/oauth/revoke") {
      const form = new URLSearchParams(await read(req));
      state.revoked.push(form.get("token") ?? "");
      refreshTokens.delete(form.get("token") ?? "");
      res.writeHead(200);
      return res.end();
    }
    if (req.method === "GET" && url.pathname === "/v1/models") {
      state.modelsAsked += 1;
      if (!bearer) return json(res, 401, { error: { code: "subscription_sharing_invalid_user" } });
      return json(res, 200, { models: state.models });
    }
    if (req.method !== "POST" || url.pathname !== "/v1/responses") return json(res, 404, { error: { code: "not_found" } });
    const text = await read(req);
    let body: Record<string, unknown> = {};
    try {
      body = JSON.parse(text) as Record<string, unknown>;
    } catch {
      return json(res, 400, { error: { code: "invalid_json" } });
    }
    state.asks.push({ headers: req.headers, body });
    if (!bearer) return json(res, 401, { error: { code: "subscription_sharing_invalid_user" } });
    const reply = next;
    switch (reply.kind) {
      case "answer":
        return sse(res, [{ type: "response.created" }, ...deltas(reply.text), { type: "response.output_text.done", text: reply.text }, { type: "response.completed", response: { status: "completed" } }]);
      case "limit_before":
        return json(res, 429, { error: { code: "subscription_sharing_usage_limit_exceeded", message: "Usage limit reached." } });
      case "limit_midway":
        return sse(res, [{ type: "response.created" }, ...deltas('{"summary": "Half'), { type: "response.failed", response: { error: { code: "subscription_sharing_usage_limit_exceeded" } } }]);
      case "not_eligible":
        return json(res, 403, { error: { code: "subscription_sharing_user_not_eligible" } });
      case "unavailable":
        return json(res, 503, { error: { code: "subscription_sharing_usage_unavailable" } });
      case "invalid_user":
        return json(res, 401, { error: { code: "subscription_sharing_invalid_user" } });
      case "admission":
        return json(res, reply.status, { detail: "A made-up admission answer." });
      case "incomplete":
        return sse(res, [{ type: "response.created" }, { type: "response.incomplete", response: { incomplete_details: { reason: "made_up" } } }]);
      case "cut_short":
        return sse(res, [{ type: "response.created" }, ...deltas('{"summary": "Cut')]);
    }
  };
  const server = createServer((req, res) => void handle(req, res));

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  state.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  state.stop = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return state;
}
