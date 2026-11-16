# BotControl

Private Discord bot management dashboard. BotControl runs as a Node.js web service on Render and keeps bot tokens, Render credentials, OAuth secrets, and Supabase service credentials on the server.

## Current implementation

- Discord OAuth2 sign-in with `identify guilds` scopes.
- Automatic access: a user can manage a bot on a Discord server only when they own that server or have the Discord `Administrator` permission and the bot is a member of that same server.
- Discord server permissions are checked by the backend on guild listing and every settings read/write request.
- The Discord OAuth access token is encrypted in the signed, HTTP-only session cookie and is never returned to browser JavaScript.
- Owner-only bot registry, Render restart controls, and audit logs.
- Supabase-backed bot registry, per-guild settings, user profiles, and audit events.
- Authenticated bot control API using a shared secret.
- IvynX guild discovery and guild-specific settings.
- Dynamic settings editor driven by each bot's manifest.

## Important

This branch is a development build. It has not been production-tested. Run the Supabase SQL migration and configure the required Render environment variables before exposing it. Each bot must expose the documented control API endpoints. See [BACKEND.md](BACKEND.md) for setup and security details.
