-- Run this once in the Supabase SQL Editor.
-- The service-role key is used only by the BotControl backend on Render.
-- Never expose it in the browser or commit a real key.

create table if not exists public.botcontrol_users (
  discord_id text primary key,
  username text not null,
  global_name text not null default '',
  avatar text,
  last_login_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create table if not exists public.botcontrol_bots (
  id text primary key,
  name text not null,
  render_service_id text not null,
  control_url text not null,
  enabled boolean not null default true,
  created_by text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.botcontrol_access (
  discord_id text not null,
  bot_id text not null,
  guild_id text not null default '*',
  can_view boolean not null default true,
  can_configure boolean not null default false,
  can_restart boolean not null default false,
  granted_by text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (discord_id, bot_id, guild_id)
);

create table if not exists public.botcontrol_guild_configs (
  guild_id text primary key,
  config jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create table if not exists public.botcontrol_audit (
  id bigint generated always as identity primary key,
  actor_discord_id text not null,
  actor_username text not null,
  action text not null,
  bot_id text,
  guild_id text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists botcontrol_access_user_idx
  on public.botcontrol_access (discord_id, bot_id);
create index if not exists botcontrol_audit_created_idx
  on public.botcontrol_audit (created_at desc);
create index if not exists botcontrol_audit_actor_idx
  on public.botcontrol_audit (actor_discord_id);

alter table public.botcontrol_users enable row level security;
alter table public.botcontrol_bots enable row level security;
alter table public.botcontrol_access enable row level security;
alter table public.botcontrol_guild_configs enable row level security;
alter table public.botcontrol_audit enable row level security;

-- No anon/authenticated policies are intentionally created.
-- Only the server-side service-role key may read or modify these tables.
