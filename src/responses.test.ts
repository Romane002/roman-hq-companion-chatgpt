// The one request to the owner's ChatGPT plan (chatgpt/responses.ts; SPEC v1.13 INT-10 (d), (f); ROADMAP M10, L10.2;
// D-247) against a stand-in OpenAI (./stand-in.ts): what is sent, the stream read to `response.completed`,
// and every answer that is not one, OpenAI's usage limit above all. Made-up words only (G-17).
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { startChatgptStandIn, type ChatgptStandIn } from "./stand-in.ts";
import { failureOf, listModels, requestBody, respond, type Ask } from "./responses.ts";

const TOKEN = "made-up-access-token";
let chatgpt: ChatgptStandIn;
beforeAll(async () => {
  chatgpt = await startChatgptStandIn(TOKEN);
});
afterAll(() => chatgpt.stop());

const send = (url: string, init?: RequestInit) => fetch(url, init);
const ask: Ask = { model: "made-up-model", instructions: "Made-up instructions.", input: "Title: A made-up talk\nChannel: Nobody\nTranscript:\nWords.", schema: { name: "made_up", schema: { type: "object" } } };

// The fields OpenAI's "Preview limitations" page says to omit in this flow.
const UNSUPPORTED = ["background", "conversation", "max_output_tokens", "max_tool_calls", "metadata", "moderation", "multi_agent", "prompt", "prompt_cache_retention", "safety_identifier", "temperature", "top_logprobs", "top_p", "truncation", "user", "previous_response_id", "tools"];

describe("the one request", () => {
  test("sends the model, the instructions, one input and the answer's shape, with store false and a stream", async () => {
    chatgpt.reply({ kind: "answer", text: '{"summary":"A made-up summary.","takes":["One.","Two."]}' });
    const answer = await respond(send, TOKEN, ask, chatgpt.url);
    expect(answer).toEqual({ kind: "answer", text: '{"summary":"A made-up summary.","takes":["One.","Two."]}' });
    const sent = chatgpt.asks.at(-1)!;
    expect(sent.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(Object.keys(sent.body).sort()).toEqual(["input", "instructions", "model", "store", "stream", "text"]);
    expect(sent.body).toMatchObject({ model: "made-up-model", instructions: "Made-up instructions.", store: false, stream: true });
    expect(sent.body.input).toEqual([{ role: "user", content: ask.input }]);
    expect(sent.body.text).toEqual({ format: { type: "json_schema", name: "made_up", schema: { type: "object" }, strict: true } });
    for (const field of UNSUPPORTED) expect(sent.body, field).not.toHaveProperty(field);
    // No other way to pay: the bearer is the one credential, no key header of any kind.
    expect(Object.keys(sent.headers).filter((name) => /key|openai-/i.test(name))).toEqual([]);
  });

  test("the body is built the same way without a shape", () => {
    expect(requestBody({ model: "m", instructions: "i", input: "x" })).toEqual({ model: "m", instructions: "i", input: [{ role: "user", content: "x" }], store: false, stream: true });
  });

  test("OpenAI's usage limit, before the stream or in the middle of it, is the limit", async () => {
    chatgpt.reply({ kind: "limit_before" });
    expect(await respond(send, TOKEN, ask, chatgpt.url)).toMatchObject({ kind: "failure", failure: "limit", status: 429, code: "subscription_sharing_usage_limit_exceeded" });
    chatgpt.reply({ kind: "limit_midway" });
    expect(await respond(send, TOKEN, ask, chatgpt.url)).toMatchObject({ kind: "failure", failure: "limit", code: "subscription_sharing_usage_limit_exceeded" });
  });

  test("plan use not allowed, OpenAI unavailable, a sign-in not accepted, each by OpenAI's own code", async () => {
    chatgpt.reply({ kind: "not_eligible" });
    expect(await respond(send, TOKEN, ask, chatgpt.url)).toMatchObject({ failure: "not_allowed", status: 403 });
    chatgpt.reply({ kind: "unavailable" });
    expect(await respond(send, TOKEN, ask, chatgpt.url)).toMatchObject({ failure: "busy", status: 503 });
    chatgpt.reply({ kind: "invalid_user" });
    expect(await respond(send, TOKEN, ask, chatgpt.url)).toMatchObject({ failure: "signed_out", status: 401 });
    expect(await respond(send, "another-made-up-token", ask, chatgpt.url)).toMatchObject({ failure: "signed_out" });
  });

  test("an admission answer without OpenAI's error object is read by its status alone", async () => {
    for (const [status, failure] of [[401, "signed_out"], [403, "not_allowed"], [503, "busy"]] as const) {
      chatgpt.reply({ kind: "admission", status });
      expect(await respond(send, TOKEN, ask, chatgpt.url)).toMatchObject({ failure, status, code: null });
    }
  });

  test("an incomplete response or a stream cut short is not an answer", async () => {
    chatgpt.reply({ kind: "incomplete" });
    expect(await respond(send, TOKEN, ask, chatgpt.url)).toMatchObject({ kind: "failure", failure: "failed" });
    chatgpt.reply({ kind: "cut_short" });
    expect(await respond(send, TOKEN, ask, chatgpt.url)).toMatchObject({ kind: "failure", failure: "busy" });
  });

  test("no network is busy, never another way to answer", async () => {
    const down = () => Promise.reject(new TypeError("fetch failed"));
    expect(await respond(down, TOKEN, ask, chatgpt.url)).toMatchObject({ kind: "failure", failure: "busy", status: null });
  });

  test("OpenAI's codes come before the status", () => {
    expect(failureOf(429, "subscription_sharing_usage_limit_exceeded")).toBe("limit");
    expect(failureOf(403, "subscription_sharing_user_not_eligible")).toBe("not_allowed");
    expect(failureOf(403, "chatpass_v2_scope_not_authorized")).toBe("signed_out");
    expect(failureOf(403, "subscription_sharing_route_not_supported")).toBe("failed");
    expect(failureOf(400, "subscription_sharing_unsupported_capability")).toBe("failed");
    expect(failureOf(429, null)).toBe("busy");
    expect(failureOf(400, null)).toBe("failed");
  });
});

describe("the account's models", () => {
  test("the ones meant to be shown, in OpenAI's own order", async () => {
    expect(await listModels(send, TOKEN, chatgpt.url)).toEqual([{ slug: "made-up-model", displayName: "Made-up model" }]);
    expect(await listModels(send, "another-made-up-token", chatgpt.url)).toBe("signed_out");
  });
});
