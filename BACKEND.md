# BotControl backend setup

BotControl is a Node.js/Express Web Service. The owner and invited users authenticate through Discord OAuth2. Access control is enforced by the backend on every bot and guild request.

## 1. Supabase database

Create a Supabase project. Open **SQL Editor** and run `supabase/schema.sql` from this repository.

The schema creates:
- `botcontrol_users`: Discord profiles for users who have signed in.
- `botcontrol_access`: permissions scoped to a user, bot, and Discord server. Use `*` as `guild_id` to grant access to every server for one bot.
- `botcontrol_audit`: owner-visible history of access grants, config updates, and restarts.

Row Level Security is enabled with no public policies. BotControl accesses these tables only from its backend using the Supabase service-role key. Never put that key in browser code or GitHub.

## 2. Discord OAuth2

In the Discord Developer Portal, create or select the OAuth2 application for BotControl.

Add this exact redirect URI after your Render URL is known:

`https://YOUR-BOTCONTROL.onrender.com/auth/discord/callback`

OAuth scope required: `identify`.

Set these Render environment variables:
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI` (must exactly match the Developer Portal redirect)
- `BOTCONTROL_OWNER_DISCORD_ID` (your Discord user ID)
- `SESSION_SECRET` (a long random value)

The first owner login is automatic when the Discord ID matches `BOTCONTROL_OWNER_DISCORD_ID`. Other users are rejected until the owner grants them access from the **Доступы** page.

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

## 4. Update IvynX

Deploy the matching `botcontrol-v2-guild-settings` branch of the IvynX repository. Set `BOTCONTROL_SHARED_SECRET` on its Render service.

On the IvynX Render service, set `DISCORD_TOKEN`, `BOTCONTROL_SHARED_SECRET`, `SUPABASE_URL`, and `SUPABASE_SERVICE_ROLE_KEY`.

IvynX now exposes:
- `GET /control/manifest` (describes the settings this bot supports)
- `GET /control/guilds`
- `GET /control/config?guild_id=DISCORD_SERVER_ID`
- `PUT /control/config?guild_id=DISCORD_SERVER_ID`

Every settings request requires a valid guild ID, and the bot must actually be a member of that server. Runtime configuration is stored under separate guild IDs in Supabase table `botcontrol_guild_configs` and cached in `config.json` on the bot service.

## 5. Granting access

1. Sign into BotControl with the owner Discord account.
2. Open **Доступы**.
3. Enter the invited user's Discord ID and bot ID (for IvynX: `ivynx`).
4. Enter `*` for all guilds of that bot, or a single Discord server ID.
5. Select view, configure, and/or restart permissions.
6. Save. The invited user can now sign in with Discord.

The user must be granted at least one access row before OAuth sign-in is accepted.

## Security and limitations

- Discord OAuth tokens are exchanged server-side and are not exposed to the browser.
- Session cookies are signed, HTTP-only, Secure in production, and expire after 12 hours.
- Access checks happen server-side for every bot, guild, configuration, and restart request.
- Render service IDs are allowlisted through `BOT_SERVICES`.
- Bot-to-panel requests use a shared bearer secret.
- Audit writes are best-effort; if Supabase is unavailable, the action may still complete but its audit event may not be stored.
- Render host status is not proof that the Discord Gateway connection is healthy.
- This branch is not yet production-ready until the workflow checks pass and the OAuth/Supabase/Render configuration is completed.
