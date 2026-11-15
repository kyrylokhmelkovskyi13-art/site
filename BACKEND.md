# BotControl backend

This repository now includes a Node.js/Express backend. It serves the existing dashboard and exposes a small owner-only API.

## What is implemented

- Owner login using the server-side `OWNER_PASSWORD` secret.
- Signed, HTTP-only, SameSite=Strict session cookie (12-hour lifetime).
- Origin checks on state-changing requests.
- Basic per-IP login attempt limiting.
- `GET /api/health` health check.
- `GET /api/auth/me`, `POST /api/auth/login`, `POST /api/auth/logout`.
- `GET /api/bots` reads configured Render services.
- `POST /api/bots/:id/restart` restarts only a service explicitly listed in `BOT_SERVICES`.
- `GET /api/bots/:id/config` reads the bot configuration through its authenticated control API.
- `PUT /api/bots/:id/config` validates and applies live configuration changes without restarting the bot.

## Configure on Render

1. Create a new **Web Service** from this GitHub repository.
2. Runtime: Node. Build command: `npm install`. Start command: `npm start`.
3. Add environment variables in Render:
   - `OWNER_PASSWORD`: a long, unique dashboard password.
   - `SESSION_SECRET`: a random secret with at least 32 bytes.
   - `RENDER_API_TOKEN`: a Render API key. Keep it only in Render's secret environment settings.
   - `BOTCONTROL_SHARED_SECRET`: a long random secret; set the same value in BotControl and the IvynX bot service.
   - `BOT_SERVICES`: JSON array containing the Render service ID and bot service base URL:
     `[{"id":"ivynx","name":"Kingdom of IvynX","renderServiceId":"srv-dbssmff3r2c73b9d05g","controlUrl":"https://ivynx.onrender.com"}]`
4. Do not put bot tokens, Render API keys, or passwords in `index.html`, browser JavaScript, or GitHub.
5. Open the service URL after deployment.

You can also deploy the included `render.yaml` Blueprint. It deliberately leaves secret values for you to enter.

## Important limitations

- The API reports **Render host/service status**, not Discord Gateway presence. A running web service does not prove that the Discord bot is connected.
- The dashboard includes an owner-only live settings editor for the IvynX bot. It requires the bot API deployment and matching shared secret.
- Live application logs and Discord guild/member/latency metrics are not implemented yet.
- The IvynX service must deploy the matching control API and have `BOTCONTROL_SHARED_SECRET` set to the exact same value. Its `config.json` is stored on the bot service filesystem; configure persistent storage on that service if the host filesystem is ephemeral, otherwise config changes may be lost after a redeploy/restart.
- Restart is a real action against Render once a valid API key and service ID are configured. The API only permits IDs in the server-side allowlist.
- Render API keys are powerful secrets. Use a dedicated key if possible and revoke it if exposed.

## Local development

```bash
npm install
cp .env.example .env
# Edit .env with local test values; never commit it.
npm start
```

Node.js 20 or newer is required.
