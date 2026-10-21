create table if not exists public.app_testers (
  id text primary key,
  app_id text not null references public.apps(id) on delete cascade,
  email text not null,
  name text not null default '',
  status text not null default 'invited',
  created_at bigint not null default floor(extract(epoch from now()))::bigint
);

alter table public.app_testers
  add column if not exists invite_token_hash text,
  add column if not exists invite_expires_at bigint,
  add column if not exists access_token_hash text,
  add column if not exists access_expires_at bigint,
  add column if not exists accepted_at bigint;

create unique index if not exists app_testers_invite_token_hash_uidx
  on public.app_testers (invite_token_hash)
  where invite_token_hash is not null;

create unique index if not exists app_testers_access_token_hash_uidx
  on public.app_testers (access_token_hash)
  where access_token_hash is not null;

create index if not exists app_testers_app_status_idx
  on public.app_testers (app_id, status);

create index if not exists app_testers_app_email_lower_idx
  on public.app_testers (app_id, lower(email));

create index if not exists releases_development_app_idx
  on public.releases (app_id, environment, status, version_code desc);
