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

## Configure on Render

1. Create a new **Web Service** from this GitHub repository.
2. Runtime: Node. Build command: `npm install`. Start command: `npm start`.
3. Add environment variables in Render:
   - `OWNER_PASSWORD`: a long, unique dashboard password.
   - `SESSION_SECRET`: a random secret with at least 32 bytes.
   - `RENDER_API_TOKEN`: a Render API key. Keep it only in Render's secret environment settings.
   - `BOT_SERVICES`: JSON array containing the exact Render service IDs, for example:
     `[{"id":"ivynx","name":"Kingdom of IvynX","renderServiceId":"srv-REAL_ID"}]`
4. Do not put bot tokens, Render API keys, or passwords in `index.html`, browser JavaScript, or GitHub.
5. Open the service URL after deployment.

You can also deploy the included `render.yaml` Blueprint. It deliberately leaves secret values for you to enter.

## Important limitations

- The API reports **Render host/service status**, not Discord Gateway presence. A running web service does not prove that the Discord bot is connected.
- The current dashboard HTML is still the original frontend preview and is not yet wired to these endpoints. The login screen and live bot cards are the next frontend integration step.
- Live application logs and Discord guild/member/latency metrics are not implemented yet.
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
