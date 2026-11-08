// The one request to the owner's ChatGPT plan (SPEC v1.13 INT-10 (d), (f); ROADMAP M10, L10.2; D-243, D-247), as
// OpenAI's pages for ChatGPT plan usage in open-source apps describe it (developers.openai.com/siwc, "Models and
// inference", "Preview limitations" and "Errors and recovery", read 2026-11-08): `POST /v1/responses` on
// api.openai.com with the signed-in account's access token as the bearer, `store: false` and `stream: true`, the
// instructions and one user input, read as a stream of events until `response.completed`. None of the fields OpenAI
// lists as unsupported is sent. This folder is the companion's part published as open source (D-243): it imports
// nothing outside itself but Node's own parts, and it is handed the function that sends a request.
//
// Within the plan's allowance only (D-247): there is no API key, no other way to pay and no retry here. OpenAI's usage
// limit, `subscription_sharing_usage_limit_exceeded`, comes back as `limit`, and HQ then holds every request until the
// owner presses "Try again" (INT-10 (f)); OpenAI "does not silently switch the request to another billing path".

export const OPENAI_API = "https://api.openai.com";

export type Send = (url: string, init?: RequestInit) => Promise<Response>;

export interface Ask {
  model: string;
  instructions: string;
  input: string;
  // The answer's JSON shape, asked as structured output.
  schema?: { name: string; schema: Readonly<Record<string, unknown>> };
}

// Why a request was not answered: the plan's limit for this app, plan use not allowed for this account, OpenAI busy
// or the network down, the sign-in no longer accepted, or anything else.
export type Failure = "limit" | "not_allowed" | "busy" | "signed_out" | "failed";
export type Answer = { kind: "answer"; text: string } | { kind: "failure"; failure: Failure; status: number | null; code: string | null; requestId: string | null };

const ANSWER_MOST = 64_000;

// OpenAI's own codes first (its "Errors and recovery" page), then the status alone; never the words of a message.
export function failureOf(status: number | null, code: string | null): Failure {
  switch (code) {
    case "subscription_sharing_usage_limit_exceeded":
      return "limit";
    case "subscription_sharing_user_not_eligible":
      return "not_allowed";
    case "subscription_sharing_usage_unavailable":
    case "subscription_sharing_user_unavailable":
      return "busy";
    case "subscription_sharing_invalid_user":
    case "chatpass_v2_scope_not_authorized":
    case "chatpass_v2_invalid_authorization_context":
      return "signed_out";
    case "subscription_sharing_unsupported_capability":
    case "subscription_sharing_route_not_supported":
      return "failed";
  }
  if (status === null) return "busy";
  if (status === 401) return "signed_out";
  if (status === 403) return "not_allowed";
  if (status === 429 || status >= 500) return "busy";
  return "failed";
}

// The request's body: the model, the instructions, one user input, the answer's shape, `store: false`, `stream: true`.
export function requestBody(ask: Ask): Record<string, unknown> {
  const body: Record<string, unknown> = { model: ask.model, instructions: ask.instructions, input: [{ role: "user", content: ask.input }] };
  if (ask.schema) body.text = { format: { type: "json_schema", name: ask.schema.name, schema: ask.schema.schema, strict: true } };
  body.store = false;
  body.stream = true;
  return body;
}

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const codeIn = (value: unknown): string | null => {
  if (!isObject(value)) return null;
  if (typeof value.code === "string") return value.code;
  if (isObject(value.error) && typeof value.error.code === "string") return value.error.code;
  return null;
};

async function errorCode(response: Response): Promise<string | null> {
  try {
    const text = await response.text();
    return codeIn(JSON.parse(text.slice(0, ANSWER_MOST)));
  } catch {
    return null;
  }
}

// The stream's events, one `data:` object each (OpenAI's server-sent events).
async function* events(response: Response): AsyncGenerator<Record<string, unknown>> {
  if (!response.body) return;
  const decoder = new TextDecoder();
  let buffer = "";
  for await (const chunk of response.body) {
    buffer += decoder.decode(chunk, { stream: true });
    let end: number;
    while ((end = buffer.search(/\r?\n\r?\n/)) >= 0) {
      const block = buffer.slice(0, end);
      buffer = buffer.slice(end).replace(/^\r?\n\r?\n/, "");
      const data = block
        .split(/\r?\n/)
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice(5).trimStart())
        .join("\n");
      if (!data) continue;
      try {
        const event: unknown = JSON.parse(data);
        if (isObject(event)) yield event;
      } catch {
        // not an event this client reads
      }
    }
  }
}

export async function respond(send: Send, accessToken: string, ask: Ask, origin: string = OPENAI_API): Promise<Answer> {
  const failure = (failure: Failure, status: number | null, code: string | null, requestId: string | null): Answer => ({ kind: "failure", failure, status, code, requestId });
  let response: Response;
  try {
    response = await send(`${origin}/v1/responses`, {
      method: "POST",
      headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json", accept: "text/event-stream" },
      body: JSON.stringify(requestBody(ask)),
    });
  } catch {
    return failure("busy", null, null, null);
  }
  const requestId = response.headers.get("x-request-id");
  if (response.status !== 200) {
    const code = await errorCode(response);
    return failure(failureOf(response.status, code), response.status, code, requestId);
  }
  let text = "";
  try {
    for await (const event of events(response)) {
      const type = event.type;
      if (type === "response.output_text.delta" && typeof event.delta === "string") {
        text += event.delta;
        if (text.length > ANSWER_MOST) return failure("failed", 200, "answer_too_long", requestId);
      } else if (type === "response.completed") {
        return { kind: "answer", text };
      } else if (type === "response.failed") {
        const code = isObject(event.response) ? codeIn(event.response.error) : null;
        return failure(failureOf(200, code), 200, code, requestId);
      } else if (type === "response.incomplete") {
        return failure("failed", 200, "incomplete", requestId);
      } else if (type === "error") {
        const code = codeIn(event);
        return failure(failureOf(200, code), 200, code, requestId);
      }
    }
  } catch {
    return failure("busy", 200, "interrupted", requestId);
  }
  // A stream that ends without `response.completed` is not an answer (OpenAI's "Wait for completed inference").
  return failure("busy", 200, "interrupted", requestId);
}

export interface Model {
  slug: string;
  displayName: string;
}

// The signed-in account's models, in OpenAI's own order, those meant to be shown only (`visibility: "list"`).
export async function listModels(send: Send, accessToken: string, origin: string = OPENAI_API): Promise<Model[] | Failure> {
  let response: Response;
  try {
    response = await send(`${origin}/v1/models`, { method: "GET", headers: { authorization: `Bearer ${accessToken}` } });
  } catch {
    return "busy";
  }
  if (response.status !== 200) return failureOf(response.status, await errorCode(response));
  try {
    const json: unknown = await response.json();
    const models = isObject(json) && Array.isArray(json.models) ? json.models : [];
    return models
      .filter((model): model is Record<string, unknown> => isObject(model) && typeof model.slug === "string" && model.visibility === "list")
      .map((model) => ({ slug: model.slug as string, displayName: typeof model.display_name === "string" ? model.display_name : (model.slug as string) }));
  } catch {
    return "failed";
  }
}
