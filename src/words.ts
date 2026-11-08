// OpenAI's own words for ChatGPT plan use, as its "UI and UX guidelines" page gives them (developers.openai.com/siwc,
// read 2026-11-08), and the address its "Manage usage" opens: ChatGPT's usage settings, where the owner reviews the
// plan's use and this app's limit. Part of the companion's open-source part (D-243): nothing but these words.
export const OPENAI_WORDS = {
  continue: "Continue with ChatGPT",
  noticeTitle: "You're using your ChatGPT plan",
  noticeBody: "Eligible usage in this app uses your ChatGPT plan. Manage usage in your ChatGPT settings.",
  gotIt: "Got it",
  plan: "Using ChatGPT plan",
  manage: "Manage usage",
} as const;

export const MANAGE_USAGE = "https://chatgpt.com/settings/usage";
