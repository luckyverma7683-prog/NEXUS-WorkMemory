# NEXUS

NEXUS is a multi-user workspace app. Users can create an account with an email address and password; optional Google sign-in and provider connections can also be enabled. Each account has its own sessions, integrations, and uploaded documents. Passwords are stored as salted scrypt hashes, OAuth tokens and uploaded text are encrypted in the local SQLite database, and provider credentials are never stored in browser storage. The Gemini API key stays on the server.

## Technology stack

- **Runtime:** Node.js 22.5 or newer, using the built-in HTTP server and `node:sqlite`.
- **Server:** JavaScript on Node.js, with built-in cryptography, password hashing, sessions, and provider API integrations.
- **User interface:** HTML, CSS, and browser JavaScript served directly by the Node.js app; no frontend build step is required.
- **Storage:** SQLite for local accounts, sessions, encrypted provider credentials, and uploaded documents.
- **AI:** Gemini API for chat answers; a Gemini API key is optional until you want to use chat.
- **Integrations:** Optional Google OAuth/Drive, GitHub App, Notion OAuth, and Slack OAuth connections.

## Fresh checkout setup

1. Install Node.js **22.5 or newer**.
2. Copy `.env.example` to `.env` in the project root. On Windows PowerShell, run `Copy-Item .env.example .env`; on macOS or Linux, run `cp .env.example .env`.
3. Edit `.env` locally. Add `GEMINI_API_KEY` to enable chat and configure credentials only for the integrations you plan to use. Keep `.env` private; do not commit or share it. The `.env.example` file contains placeholders, not working credentials.
4. If setting `NEXUS_ENCRYPTION_KEY`, replace its placeholder with a randomly generated, stable secret and keep the same value for future runs and backups. Alternatively, leave it unset and NEXUS will create a local `.nexus.key` file automatically; keep that file private and back it up securely with the database.
5. Run `npm start` from the project root and open <http://localhost:3000>. Keep the terminal open while using NEXUS.
6. Choose **Create an account**, then enter your name, email, and a password of at least 10 characters. After registration you are signed in and can use the dashboard. Email/password accounts work without Google OAuth configuration.

## Run locally

After completing the fresh checkout setup above, start NEXUS with `npm start` and open <http://localhost:3000>.

If startup says port 3000 is already in use, the server is already running (or another program owns that port). Open <http://localhost:3000> first. If it is not NEXUS, stop the old server from the terminal where it was started with Ctrl+C, then run `npm start` once.

Google sign-in is optional and requires OAuth setup below. GitHub, Drive, Notion, and Slack connections each require their own provider application credentials. The source connection screen explains the requested read permissions and initiates the actual provider consent/install flow. Local Documents uploads accept `.txt`, `.md`, `.csv`, and `.json` files up to 1 MB each.

## Configure OAuth providers

OAuth callback URLs use your configured `NEXUS_PUBLIC_URL`:

- Google sign-in and Drive: `/auth/callback/google`
- GitHub App installation: `/auth/callback/github`
- Notion: `/auth/callback/notion`
- Slack: `/auth/callback/slack`

### Google sign-in and Drive

In Google Cloud Console, create an OAuth client of type **Web application**. Add the exact NEXUS origin as an authorized JavaScript origin and the callback above as an authorized redirect URI. When testing at a different origin, use that same host consistently in the browser, `NEXUS_PUBLIC_URL`, authorized JavaScript origin, and registered callback URI. For local development, use `localhost` rather than `127.0.0.1`. Enable Google Drive API. Put the client ID and client secret in `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`. The Google consent screen needs the `openid`, `email`, and `profile` identity scopes; connecting Drive separately requests read-only `drive.readonly` access.

Google may require OAuth consent-screen configuration, test users, sensitive-scope verification, and an approved publishing status before general users can connect Drive.

### GitHub

Create a **GitHub App** (not an OAuth App), set its callback URL to the full NEXUS `/auth/callback/github` URL, and set its setup URL to that same URL. For local presentation, use `http://localhost:3000/auth/callback/github` and open NEXUS at `http://localhost:3000` consistently. Configure **Contents: Read-only**, **Issues: Read-only**, and **Pull requests: Read-only** permissions; keep all write permissions disabled. Enable installation on the account types you need. Set the App ID and URL slug as `GITHUB_APP_ID` and `GITHUB_APP_SLUG`. Paste the downloaded private key into `GITHUB_PRIVATE_KEY` as one quoted line, replacing each actual newline with the literal characters `\n`.

Users choose which repositories the GitHub App can access during installation. NEXUS requests a short-lived installation token limited to read-only Contents, Issues, and Pull requests permissions, checks that GitHub granted those permissions, and does not persist the token. The dashboard labels GitHub setup as required until all three server settings are present and the private key is valid. GitHub will still reject invalid App IDs/slugs, incorrect callback URLs, or an App that is not installed; NEXUS reports those as real provider errors rather than marking the connection successful.

### Notion

Create a Notion **public OAuth integration**, register the callback URL, and put its OAuth client ID and secret in `NOTION_CLIENT_ID` and `NOTION_CLIENT_SECRET`. Users must share pages with the integration; only shared pages are accessible.

### Slack

Create a Slack app, register the callback URL, and configure OAuth scopes `channels:read`, `channels:history`, `groups:read`, `groups:history`, and `users:read`. Put its client ID and secret in `SLACK_CLIENT_ID` and `SLACK_CLIENT_SECRET`. The bot can read messages only in channels it can access; invite it to private channels the user wants NEXUS to search.

## Self-hosting on your own server

1. Deploy behind a trusted HTTPS reverse proxy (for example, Caddy or Nginx); do not expose the Node port directly to the internet.
2. Set `NEXUS_PUBLIC_URL` to the public HTTPS origin (for example, `https://nexus.example.com`) and register the provider callback URLs above. Set `HOST=127.0.0.1` and choose a private port.
3. Configure secrets as server environment variables or in a `.env` file readable only by the service account. Never commit `.env`, provider private keys, database files, or the encryption key.
4. Before first start, set `NEXUS_ENCRYPTION_KEY` to a randomly generated, stable 32-byte secret. Generate one with `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`. Back it up separately and keep the same value across restarts and backups; changing or losing it makes stored OAuth credentials unreadable.
5. Run `npm start` under a service manager. Keep the `.nexus.sqlite` database and encryption key on persistent, access-controlled storage. Back them up together securely.

This starter uses a **single Node.js process and local SQLite database**. Do not run multiple app replicas against separate local disks; users would get inconsistent accounts and connections. A larger production deployment should move sessions, encrypted integration storage, rate limiting, and uploads to managed shared services, and should add operational monitoring, backup/restore testing, and a privacy/retention policy.

### Current data use

- Google Drive metadata and recent readable text files/Google Docs, selected GitHub repositories, shared Notion pages, and accessible Slack channel messages are fetched on demand to answer a chat question.
- Local uploads are encrypted and scoped to the signed-in user. They are sent to Gemini as context when that user asks a question.
- NEXUS currently fetches a bounded set of recent provider items per question; it is not a background crawler or a complete searchable index. Binary Drive files and PDFs are listed but not parsed.
- Disconnecting in NEXUS removes its saved credentials. Users should also revoke the NEXUS app from Google, GitHub, Notion, or Slack account settings to remove the provider-side grant.
- This is a self-hostable starter, not a security/compliance certification. Review scopes, public provider verification requirements, retention, backups, and your reverse proxy configuration before inviting other users.
- Accounts use salted scrypt password hashes and server-side sessions. This starter does not send email verification or password-reset messages; for a public service, configure a mail provider and add those account recovery controls before inviting users.
