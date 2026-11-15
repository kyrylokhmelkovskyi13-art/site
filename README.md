# BotControl

Private dashboard for managing Discord bot hosting services.

## Current status

- Responsive dashboard UI with owner login.
- Node.js/Express backend with signed HTTP-only sessions.
- Owner-only API to inspect configured Render services and request a restart.
- Render credentials and owner password are read only from server environment variables.
- The API allowlists service IDs through `BOT_SERVICES`.

See [BACKEND.md](BACKEND.md) for setup and deployment instructions.

## Run locally

Requires Node.js 20+.

```bash
npm install
cp .env.example .env
# Fill in local environment values; never commit .env.
npm start
```

## Deploy

The repository includes `render.yaml` for a Render Blueprint. You must still create/deploy the service and set the secret environment values in Render.

**Important:** The dashboard reports Render service status, not Discord Gateway presence. Live Discord metrics and application log streaming are not implemented yet.
