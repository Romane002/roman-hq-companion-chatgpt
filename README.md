# Roman HQ companion: the ChatGPT part

The part of the Roman HQ companion that talks to ChatGPT, published as open source. It lets a program on your Mac use
your own ChatGPT plan through OpenAI's Sign in with ChatGPT for open-source apps, never an API key, and stops at your
plan's limits.

- `src/oauth.ts`: the sign-in: PKCE, a one-answer callback on 127.0.0.1, the app registered at the first sign-in, the
  access token renewed near its end, sign-out revoking the session.
- `src/jwt.ts`: the ID token checked against OpenAI's published keys.
- `src/responses.ts`: one request to `/v1/responses` with `store: false`, read as a stream; OpenAI's usage limit
  reported, never worked around.
- `src/keychain.ts`: secrets kept in the Mac's Keychain through macOS's `security` tool, never on a command line.
- `src/words.ts`: OpenAI's own words for plan use, and the address of ChatGPT's usage settings.
- `src/stand-in.ts` and the tests: a stand-in OpenAI on your own machine, with made-up accounts.

It uses Node 24's own parts only and has no dependencies to run.

    npm install
    npm test

Built from OpenAI's pages for ChatGPT plan usage in open-source apps: https://developers.openai.com/siwc (read
2026-11-08).

These files are copied from a private project, where they are written and tested; a change is made there and copied
here.

MIT licence: see LICENSE.
