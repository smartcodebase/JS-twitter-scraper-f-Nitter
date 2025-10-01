Nitter JS Scraper
=================

Minimal Node.js script to fetch tweets for a specific user using X (Twitter) GraphQL endpoints with OAuth1 credentials.

Setup
-----

1) Node 18+ recommended.

2) Install dependencies:

```
npm install
```

3) Create a `.env` file from the example and fill in OAuth credentials:

```
cp .env.example .env
```

Environment variables:

- `X_CONSUMER_KEY`
- `X_CONSUMER_SECRET`
- `X_OAUTH_TOKEN`
- `X_OAUTH_TOKEN_SECRET`

Run
---

Fetch a user timeline (tweets by default):

```
node src/cli.js jack --kind tweets
```

Options:

- `--kind` one of `tweets`, `replies`, `media`
- `--cursor` pagination cursor
- `--json=false` to print a compact summary instead of raw JSON

Notes
-----

- X frequently rotates GraphQL endpoint identifiers. The endpoints used here mirror those in `src/consts.nim` and may need updating if requests start failing.
- The script signs requests using OAuth1 and does not rely on cookies.



