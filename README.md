# BotControl

Private Discord bot management dashboard. BotControl runs as a Node.js web service on Render and keeps all bot tokens, Render credentials, OAuth secrets, and Supabase service credentials on the server.

## Current implementation on `botcontrol-v2-guild-settings`

- Discord OAuth2 sign-in.
- Owner identity configured by `BOTCONTROL_OWNER_DISCORD_ID`.
- Owner-managed per-user access grants scoped to a bot and either one Discord server or all servers for that bot.
- Separate permissions for viewing settings, changing settings, and restarting a bot.
- Supabase-backed access records and audit events.
- Render service status and allowlisted restart requests.
- Authenticated bot control API using a shared secret.
- IvynX guild discovery and guild-specific settings.
- Owner-only access management and audit log pages.

## Important

This branch is a development build. It has not been deployed or production-tested. Run the Supabase SQL migration and configure the required Render environment variables before exposing it. The dashboard currently has a dedicated settings editor for the IvynX adapter; other bots need their own settings adapter/manifest before their controls can be rendered.

See [BACKEND.md](BACKEND.md) for setup and security details.
