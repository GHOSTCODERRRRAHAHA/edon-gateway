# Super-Agent Setup — Edonbot/Telegram + EDON

This guide wires **Brave Search**, **Gmail**, **Google Calendar**, **ElevenLabs**, and **GitHub** into the EDON Gateway so your Edonbot/Telegram bot can act as a super agent (research, email, calendar, voice, code).

---

## Architecture

- **Edonbot/Telegram** → user chats with the bot.
- **Bot** → sends actions to EDON Gateway `POST /execute` (with `X-EDON-TOKEN`).
- **EDON** → evaluates with governor, then runs the right connector (Brave Search, Gmail, etc.).
- **Credentials** → stored in EDON (DB or env); the bot never sees API keys.

---

## 1. Brave Search (web research)

**Get key:** [Brave Search API](https://api.search.brave.com/) → create app → copy **API key**.

**Env (dev):**
```bash
BRAVE_SEARCH_API_KEY=your-brave-api-key
```

**Or store in DB** via your credentials API (tool_name: `brave_search`, credential_data: `{"api_key": "..."}`).

**Execute from Edonbot/agent:**
```json
{
  "action": {
    "tool": "brave_search",
    "op": "search",
    "params": {
      "q": "latest news on AI",
      "count": 10,
      "country": "US",
      "freshness": "pd"
    }
  },
  "agent_id": "edonbot-001"
}
```

**Ops:** `search` (params: `q`, `count`, `country`, `freshness`).

---

## 2. Gmail (inbox / send)

**Auth:** OAuth2 access token **or refresh token** (recommended for production).  
If you store `refresh_token` + `client_id` + `client_secret`, EDON will auto-refresh and persist `access_token` + `expires_at`.

**Env (dev):**
```bash
GMAIL_ACCESS_TOKEN=ya29....
GMAIL_REFRESH_TOKEN=1//...
GMAIL_CLIENT_ID=your-client-id
GMAIL_CLIENT_SECRET=your-client-secret
GMAIL_TOKEN_URI=https://oauth2.googleapis.com/token
GMAIL_EXPIRES_AT=1710000000
```

**Or DB:** credential_data example (tool_name: `gmail`):
```json
{
  "access_token": "ya29....",
  "refresh_token": "1//...",
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "token_uri": "https://oauth2.googleapis.com/token",
  "expires_at": 1710000000
}
```

**Execute:**
- **List messages:** `op: "list_messages"`, params: `max_results`, `q` (Gmail query), `label_ids`.
- **Get message:** `op: "get_message"`, params: `message_id`, `format`.
- **Send:** `op: "send"`, params: `to` or `recipients`, `subject`, `body`.

---

## 3. Google Calendar (events)

**Auth:** Same as Gmail — OAuth2 access token or refresh token with Calendar API scope.

**Env (dev):**
```bash
GOOGLE_CALENDAR_ACCESS_TOKEN=ya29....
GOOGLE_CALENDAR_REFRESH_TOKEN=1//...
GOOGLE_CALENDAR_CLIENT_ID=your-client-id
GOOGLE_CALENDAR_CLIENT_SECRET=your-client-secret
GOOGLE_CALENDAR_TOKEN_URI=https://oauth2.googleapis.com/token
GOOGLE_CALENDAR_EXPIRES_AT=1710000000
```

**Or DB:** credential_data example (tool_name: `google_calendar`):
```json
{
  "access_token": "ya29....",
  "refresh_token": "1//...",
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "token_uri": "https://oauth2.googleapis.com/token",
  "expires_at": 1710000000,
  "calendar_id": "primary"
}
```

**Execute:**
- **List events:** `op: "list_events"`, params: `calendar_id`, `time_min`, `time_max`, `max_results`, `single_events`.
- **Create event:** `op: "create_event"`, params: `calendar_id`, `summary`, `description`, `start`, `end`, `location` (start/end in RFC3339 or date).

---

## 4. ElevenLabs (voice / TTS)

**Get key:** [ElevenLabs](https://elevenlabs.io/) → Profile → API key.

**Env (dev):**
```bash
ELEVENLABS_API_KEY=your-xi-api-key
```

**Or DB:** credential_data: `{"api_key": "..."}` (tool_name: `elevenlabs`).

**Execute:**
- **Text-to-speech:** `op: "text_to_speech"`, params: `text`, `voice_id`, `model_id`, `voice_settings`.
- **List voices:** `op: "list_voices"`.

---

## 5. GitHub (repos, files, issues)

**Get token:** GitHub → Settings → Developer settings → Personal access tokens (repo scope).

**Env (dev):**
```bash
GITHUB_TOKEN=ghp_....
```

**Or DB:** credential_data: `{"token": "..."}` (tool_name: `github`).

**Execute:**
- **List repos:** `op: "list_repos"`, params: `visibility`, `per_page`.
- **Get file:** `op: "get_file"`, params: `owner`, `repo`, `path`.
- **Create issue:** `op: "create_issue"`, params: `owner`, `repo`, `title`, `body`, `labels`.

---

## Intent scope (governor)

For the governor to **allow** these tools, the intent scope must include them. Example intent when setting up the session:

```json
{
  "objective": "Super agent: search, email, calendar, voice, github",
  "scope": {
    "brave_search": ["search"],
    "gmail": ["list_messages", "get_message", "send"],
    "google_calendar": ["list_events", "create_event"],
    "elevenlabs": ["text_to_speech", "list_voices"],
    "github": ["list_repos", "get_file", "create_issue"]
  },
  "constraints": {},
  "risk_level": "medium",
  "approved_by_user": true
}
```

If you use **Edonbot** with `tool: "clawdbot"`, `op: "invoke"`, then the underlying bot gateway can expose its own tools; use `allowed_clawdbot_tools` in intent constraints to allowlist them. The connectors above are **native EDON tools** — the agent sends `tool: "brave_search"` (etc.) directly to EDON.

---

## Quick checklist

| Integration      | Env var                         | Get key / token from                    |
|------------------|----------------------------------|-----------------------------------------|
| Brave Search     | `BRAVE_SEARCH_API_KEY`          | api.search.brave.com                    |
| Gmail            | `GMAIL_ACCESS_TOKEN`            | Google OAuth2 (Gmail API)               |
| Google Calendar  | `GOOGLE_CALENDAR_ACCESS_TOKEN`  | Google OAuth2 (Calendar API)             |
| ElevenLabs       | `ELEVENLABS_API_KEY`            | elevenlabs.io → API key                  |
| GitHub           | `GITHUB_TOKEN`                 | GitHub → Personal access token          |

Set the env vars (or store credentials in the DB), then call `POST /execute` with the `action` objects above. Your Telegram/Edonbot bot uses your EDON token (`X-EDON-TOKEN`) so all usage is governed and audited.

---

## Optional: more integrations later

The same pattern works for:

- **Google Maps** — new connector + Tool enum + _execute_tool branch.
- **Notion / Todoist / Slack / Discord** — store token in EDON, add connector, wire in main.
- **Weather / News / Plaid** — same (env or DB credential, connector, tool enum, governor keywords).

Credentials stay in EDON; Edonbot/Telegram only sends high-level actions and never sees API keys.
