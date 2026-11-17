# BotControl backend setup

BotControl is a Node.js/Express web service. Users sign in through Discord OAuth2. Access to each bot's settings is based on current Discord server permissions, not manual invitations.

## 1. Supabase database

Open the Supabase SQL Editor and run `supabase/schema.sql`.

The schema creates:
- `botcontrol_users`: Discord profiles.
- `botcontrol_bots`: bots registered through the owner dashboard (existing `BOT_SERVICES` entries remain supported).
- `botcontrol_guild_configs`: per-server bot settings.
- `botcontrol_audit`: owner-visible audit events.
- `botcontrol_access`: retained for compatibility with earlier builds; it is no longer used to authorize dashboard access.

Row Level Security is enabled with no public policies. BotControl accesses these tables only from its backend using the Supabase service-role key. Never put that key in browser code or GitHub.

## 2. Discord OAuth2

In the Discord Developer Portal, create or select the OAuth2 application for BotControl.

Add this exact redirect URI:

`https://YOUR-BOTCONTROL.onrender.com/auth/discord/callback`

OAuth scopes required:
- `identify`
- `guilds`

Set these Render environment variables:
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI` (must exactly match the Developer Portal redirect)
- `BOTCONTROL_OWNER_DISCORD_ID` (your Discord user ID)
- `SESSION_SECRET` (a long random value)

Any Discord user can sign in. A user can see and configure a bot on a server only if:
1. They own that Discord server or currently have the Discord `Administrator` permission there.
2. The bot is currently a member of that same server.

BotControl checks the Discord guild list through the user's OAuth token and intersects it with the bot's own `/control/guilds` response. The backend repeats this check for settings reads and writes. If the user loses Administrator permission or the bot leaves the server, access is denied.

After changing OAuth scopes, users should sign out and sign in again so Discord issues a session with the `guilds` scope.

## 3. Render secrets and bot registration

Configure the BotControl Web Service from this repository:
- Runtime: Node
- Build: `npm install`
- Start: `npm start`
- Health check: `/api/health`

Set:
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `RENDER_API_TOKEN`
- `BOTCONTROL_SHARED_SECRET`
- `BOT_SERVICES` as a JSON array, for example:
  `[{"id":"ivynx","name":"Kingdom of IvynX","renderServiceId":"srv-REPLACE_ME","controlUrl":"https://ivynx.onrender.com"}]`

Use the same `BOTCONTROL_SHARED_SECRET` value in the BotControl service and each bot service. Never commit real values.

## 4. Bot control API

Deploy the matching `botcontrol-v2-guild-settings` branch of each bot repository. Set `BOTCONTROL_SHARED_SECRET` on its Render service.

Each bot must expose:
- `GET /control/manifest`
- `GET /control/guilds`
- `GET /control/config?guild_id=DISCORD_SERVER_ID`
- `PUT /control/config?guild_id=DISCORD_SERVER_ID`

Every settings request requires a valid guild ID, and the bot must actually be a member of that server. Runtime configuration is stored separately by guild ID.

For IvynX, the corresponding routes are present on the `botcontrol-v2-guild-settings` branch. The Render service must deploy that branch; the older `main` branch does not expose all required routes.

## 5. Permissions and security

- BotControl does not require an owner to manually add Discord IDs for normal settings access.
- Discord server ownership or the `Administrator` permission (permission bit `0x8`) is required.
- Bot membership in the same server is required.
- Permission checks happen on the server for every guild listing and settings read/write request.
- OAuth access tokens are encrypted with AES-256-GCM before being placed in the signed HTTP-only session cookie; they are not exposed to browser JavaScript.
- Session cookies are HTTP-only, Secure in production, and expire after 12 hours.
- Only the BotControl owner can register/remove bots, view audit logs, or restart Render services.
- Render service IDs are allowlisted through `BOT_SERVICES`.
- Bot-to-panel requests use a shared bearer secret.
- Audit writes are best-effort; if Supabase is unavailable, an action may complete without its audit event being stored.
- Render host status is not proof that the Discord Gateway connection is healthy.

This branch still needs a successful deployment and end-to-end testing with a non-owner Discord account before production use.
