// Sign in with ChatGPT (oauth.ts, jwt.ts; SPEC v1.13 INT-10 (b); ROADMAP M10, L10.2; D-243) against the stand-in's
// sign-in side (stand-in.ts): the first sign-in registers the app and keeps the issued client id, later ones reuse it;
// PKCE and the one-answer callback; each refusal of OpenAI's pages; the ID token's checks; plan use only with its scope;
// the access token renewed near its end, dropped when OpenAI no longer takes the refresh token; sign-out's revocation.
// Made-up accounts only (G-17).
import { generateKeyPairSync, sign } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "vitest";
import { verifyIdToken } from "./jwt.ts";
import { accessTokens, CALLBACK_PATH, discover, listenOnce, newHostId, PLAN_SCOPE, planAllowed, revoke, signIn, type CredentialKeeper, type Credentials } from "./oauth.ts";
import { ISSUED_CLIENT, startChatgptStandIn, SUBJECT, type ChatgptStandIn } from "./stand-in.ts";

const TOKEN = "made-up-access-token";
let chatgpt: ChatgptStandIn;
beforeAll(async () => {
  chatgpt = await startChatgptStandIn(TOKEN);
});
afterAll(() => chatgpt.stop());
beforeEach(() => {
  chatgpt.signIn("consent");
  chatgpt.refuseRefresh(null);
});

const send = (url: string, init?: RequestInit) => fetch(url, init);
const hostId = newHostId();
const attempt = (saved: Credentials | null = null) => signIn({ send, open: (url) => chatgpt.browser(url), hostId, saved, now: () => new Date(), origin: chatgpt.url, port: 0, timeoutMs: 10_000 });

describe("the first sign-in and the later ones", () => {
  test("the first registers the app with its name and this Mac's host id, and keeps the issued client id", async () => {
    const result = await attempt();
    expect(result.kind).toBe("signed_in");
    if (result.kind !== "signed_in") return;
    const asked = chatgpt.authorizations.at(-1)!;
    expect(asked.get("client_id")).toBe("dynamic_agent_client");
    expect(asked.get("agent_name_hint")).toBe("Roman HQ companion");
    expect(asked.get("ext_agent_host_id")).toBe(hostId);
    expect(hostId).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
    expect(asked.get("response_type")).toBe("code");
    expect(asked.get("scope")).toBe("openid profile email offline_access resource.invoke chatgpt.tokens.use.direct");
    expect(asked.get("resource")).toBe("https://api.openai.com/v1");
    expect(asked.get("code_challenge_method")).toBe("S256");
    expect(asked.get("redirect_uri")).toMatch(new RegExp(`^http://127\\.0\\.0\\.1:\\d+${CALLBACK_PATH}$`));
    expect(asked.get("state")).not.toBe(asked.get("nonce"));
    // The code is exchanged with the issued client id and the PKCE verifier; there is no client secret.
    const grant = chatgpt.grants.at(-1)!;
    expect(grant.get("grant_type")).toBe("authorization_code");
    expect(grant.get("client_id")).toBe(ISSUED_CLIENT);
    expect(grant.get("code_verifier")).toBeTruthy();
    expect(grant.get("redirect_uri")).toBe(asked.get("redirect_uri"));
    expect([...grant.keys()].sort()).toEqual(["client_id", "code", "code_verifier", "grant_type", "redirect_uri", "resource"]);
    expect(result.credentials).toMatchObject({ client_id: ISSUED_CLIENT, subject: SUBJECT, ext_agent_host_id: hostId, email: "made-up@example.com", access_token: TOKEN });
    expect(planAllowed(result.credentials)).toBe(true);
  });

  test("a later sign-in reuses the issued client id and the account's hints, without the app's name", async () => {
    const first = await attempt();
    if (first.kind !== "signed_in") throw new Error(first.kind);
    const again = await attempt(first.credentials);
    expect(again.kind).toBe("signed_in");
    const asked = chatgpt.authorizations.at(-1)!;
    expect(asked.get("client_id")).toBe(ISSUED_CLIENT);
    expect(asked.has("agent_name_hint")).toBe(false);
    expect(asked.get("id_token_hint")).toBe(first.credentials.id_token);
    expect(asked.get("login_hint")).toBe("made-up@example.com");
  });
});

describe("what a sign-in refuses", () => {
  test("an answer carrying another attempt's state is not taken, and its code never exchanged", async () => {
    const grants = chatgpt.grants.length;
    const forged = signIn({
      send,
      open: async (url) => {
        const address = new URL(url);
        address.searchParams.set("state", "a-forged-state");
        await chatgpt.browser(address.toString());
      },
      hostId,
      saved: null,
      now: () => new Date(),
      origin: chatgpt.url,
      port: 0,
      timeoutMs: 10_000,
    });
    expect(await forged).toEqual({ kind: "failed", why: "an answer for another sign-in" });
    expect(chatgpt.grants.length).toBe(grants);
  });

  test("a declined consent stops before any code is exchanged", async () => {
    const grants = chatgpt.grants.length;
    chatgpt.signIn("decline");
    expect(await attempt()).toEqual({ kind: "declined" });
    expect(chatgpt.grants.length).toBe(grants);
  });

  test("without the plan's scope the sign-in is kept, plan use off", async () => {
    chatgpt.signIn("no_plan");
    const result = await attempt();
    expect(result.kind).toBe("no_plan");
    if (result.kind === "no_plan") expect(result.credentials.scopes).not.toContain(PLAN_SCOPE);
  });

  test("a registration without its issued client id, or an answer for another one, is not taken", async () => {
    chatgpt.signIn("no_issued_client");
    expect(await attempt()).toMatchObject({ kind: "failed", why: "the registration did not finish" });
    chatgpt.signIn("consent");
    const first = await attempt();
    if (first.kind !== "signed_in") throw new Error(first.kind);
    chatgpt.signIn("another_client");
    expect(await attempt(first.credentials)).toMatchObject({ kind: "failed", why: "an answer for another registration" });
  });

  test("the ID token: another nonce, another audience, expired, or signed with another key", async () => {
    for (const [how, why] of [["wrong_nonce", "another nonce"], ["wrong_audience", "another audience"], ["expired", "expired"], ["another_key", "a signature that does not match"]] as const) {
      chatgpt.signIn(how);
      expect(await attempt(), how).toEqual({ kind: "failed", why: `the ID token: ${why}` });
    }
  });

  test("a later sign-in to another ChatGPT account does not replace this one", async () => {
    const first = await attempt();
    if (first.kind !== "signed_in") throw new Error(first.kind);
    chatgpt.signIn("another_subject");
    expect(await attempt(first.credentials)).toMatchObject({ kind: "failed", why: "another ChatGPT account" });
  });

  test("OpenAI's addresses must all be its own", async () => {
    const doc = (body: unknown) => async () => new Response(JSON.stringify(body), { status: 200 });
    await expect(discover(doc({ issuer: "https://elsewhere.example" }), chatgpt.url)).rejects.toThrow("another issuer");
    await expect(discover(doc({ issuer: chatgpt.url, authorization_endpoint: "https://elsewhere.example/a", token_endpoint: `${chatgpt.url}/t`, jwks_uri: `${chatgpt.url}/j` }), chatgpt.url)).rejects.toThrow("not OpenAI's own");
  });
});

describe("the callback on 127.0.0.1", () => {
  test("takes one answer at its path and closes", async () => {
    const callback = await listenOnce(0, 5_000);
    const base = callback.redirectUri.replace(CALLBACK_PATH, "");
    expect((await fetch(`${base}/elsewhere`)).status).toBe(404);
    expect((await fetch(`${callback.redirectUri}?code=c1&state=s1`)).status).toBe(200);
    expect((await callback.answer)?.get("code")).toBe("c1");
    await expect(fetch(`${callback.redirectUri}?code=c2&state=s2`)).rejects.toThrow();
  });

  test("gives up at its timeout", async () => {
    const callback = await listenOnce(0, 50);
    expect(await callback.answer).toBeNull();
  });
});

describe("the access token", () => {
  const keeper = (start: Credentials | null) => {
    let kept = start;
    return {
      read: async () => kept,
      write: async (c: Credentials) => void (kept = c),
      forgetTokens: async () => void (kept = kept ? { ...kept, access_token: "", refresh_token: "" } : null),
      now: () => kept,
    } satisfies CredentialKeeper & { now: () => Credentials | null };
  };

  test("used as it is until near its end, then renewed once with the issued client id", async () => {
    const first = await attempt();
    if (first.kind !== "signed_in") throw new Error(first.kind);
    const store = keeper(first.credentials);
    let clock = new Date();
    const token = accessTokens(send, store, () => clock, chatgpt.url);
    const grants = chatgpt.grants.length;
    expect(await token()).toEqual({ token: TOKEN });
    expect(chatgpt.grants.length).toBe(grants);
    clock = new Date(Date.now() + 3_590_000);
    const [a, b] = await Promise.all([token(), token()]);
    expect(a).toEqual({ token: TOKEN });
    expect(b).toEqual({ token: TOKEN });
    const renewals = chatgpt.grants.slice(grants);
    expect(renewals.length).toBe(1);
    expect(renewals[0]!.get("grant_type")).toBe("refresh_token");
    expect(renewals[0]!.get("client_id")).toBe(ISSUED_CLIENT);
    expect(renewals[0]!.has("scope")).toBe(false);
    expect(store.now()!.refresh_token).not.toBe(first.credentials.refresh_token);
  });

  test("a refresh token OpenAI no longer takes drops the tokens; no network is only busy", async () => {
    const first = await attempt();
    if (first.kind !== "signed_in") throw new Error(first.kind);
    const later = () => new Date(Date.now() + 3_590_000);
    const down = () => Promise.reject(new TypeError("fetch failed"));
    expect(await accessTokens(down, keeper(first.credentials), later, chatgpt.url)()).toEqual({ failure: "busy" });
    chatgpt.refuseRefresh("refresh_token_reused");
    const store = keeper(first.credentials);
    expect(await accessTokens(send, store, later, chatgpt.url)()).toEqual({ failure: "signed_out" });
    expect(store.now()).toMatchObject({ access_token: "", refresh_token: "", client_id: ISSUED_CLIENT });
  });

  test("no sign-in is signed out, and a sign-in without the plan's scope is not allowed", async () => {
    expect(await accessTokens(send, keeper(null), () => new Date(), chatgpt.url)()).toEqual({ failure: "signed_out" });
    chatgpt.signIn("no_plan");
    const result = await attempt();
    if (result.kind !== "no_plan") throw new Error(result.kind);
    expect(await accessTokens(send, keeper(result.credentials), () => new Date(), chatgpt.url)()).toEqual({ failure: "not_allowed" });
  });

  test("signing out revokes the renewable session", async () => {
    const first = await attempt();
    if (first.kind !== "signed_in") throw new Error(first.kind);
    const endpoints = await discover(send, chatgpt.url);
    expect(await revoke(send, endpoints, { clientId: first.credentials.client_id, refreshToken: first.credentials.refresh_token })).toBe(true);
    expect(chatgpt.revoked.at(-1)).toBe(first.credentials.refresh_token);
  });
});

describe("the ID token's check", () => {
  test("takes an ES256 key too, and refuses an algorithm it does not know", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const now = Math.floor(Date.now() / 1000);
    const make = (alg: string) => {
      const head = Buffer.from(JSON.stringify({ alg, kid: "ec-key" })).toString("base64url");
      const body = Buffer.from(JSON.stringify({ iss: "https://issuer.example", aud: "client-1", sub: "s", iat: now, exp: now + 60, nonce: "n" })).toString("base64url");
      return `${head}.${body}.${sign("sha256", Buffer.from(`${head}.${body}`), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
    };
    const keys = async () => [{ ...publicKey.export({ format: "jwk" }), kid: "ec-key" }];
    const expected = { issuer: "https://issuer.example", clientId: "client-1", nonce: "n", nowSeconds: now };
    expect((await verifyIdToken(make("ES256"), keys, expected)).ok).toBe(true);
    expect(await verifyIdToken(make("none"), keys, expected)).toEqual({ ok: false, why: "an algorithm this check does not take" });
    expect(await verifyIdToken("not.a", keys, expected)).toEqual({ ok: false, why: "not a token" });
  });
});
