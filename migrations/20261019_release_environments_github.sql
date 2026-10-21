alter table public.releases
  add column if not exists environment text not null default 'production',
  add column if not exists promoted_from_id text;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'releases_environment_check'
      and conrelid = 'public.releases'::regclass
  ) then
    alter table public.releases
      add constraint releases_environment_check
      check (environment in ('development', 'production'));
  end if;
end $$;

create index if not exists releases_app_environment_status_version_idx
  on public.releases (app_id, environment, status, version_code desc);

create index if not exists releases_promoted_from_idx
  on public.releases (promoted_from_id)
  where promoted_from_id is not null;

create table if not exists public.github_oauth_states (
  state_hash text primary key,
  user_id text not null,
  expires_at bigint not null,
  created_at bigint not null
);

create index if not exists github_oauth_states_expires_at_idx
  on public.github_oauth_states (expires_at);

create table if not exists public.github_installations (
  installation_id text primary key,
  sproutly_user_id text,
  account_id text not null default '',
  account_login text not null default '',
  account_type text not null default '',
  repository_selection text not null default '',
  suspended_at timestamptz,
  active boolean not null default true,
  updated_at bigint not null
);

create index if not exists github_installations_user_active_idx
  on public.github_installations (sproutly_user_id, active);

create table if not exists public.github_webhook_deliveries (
  delivery_id text primary key,
  event_name text not null,
  payload jsonb not null,
  received_at bigint not null
);
