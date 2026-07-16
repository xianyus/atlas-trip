-- Atlas Trip: Google login, cloud sync, and shared-trip permissions
-- Paste this entire file into Supabase Dashboard > SQL Editor > New query, then Run.

create extension if not exists pgcrypto;

create table if not exists public.atlas_trips (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  client_id text not null,
  title text not null,
  destination text not null default '',
  dates text not null default '',
  start_date date,
  end_date date,
  destination_lat double precision,
  destination_lng double precision,
  days jsonb not null default '[1]'::jsonb,
  places jsonb not null default '[]'::jsonb,
  transport jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists atlas_trips_owner_client_id_key
  on public.atlas_trips (owner_id, client_id);

create table if not exists public.atlas_trip_members (
  trip_id uuid not null references public.atlas_trips(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('editor', 'viewer')),
  accepted_at timestamptz not null default now(),
  primary key (trip_id, user_id)
);

create table if not exists public.atlas_trip_invites (
  id uuid primary key default gen_random_uuid(),
  trip_id uuid not null references public.atlas_trips(id) on delete cascade,
  trip_title text not null default '',
  email text not null,
  role text not null check (role in ('editor', 'viewer')),
  status text not null default 'pending' check (status in ('pending', 'accepted', 'revoked')),
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  unique (trip_id, email)
);

alter table public.atlas_trip_invites
  add column if not exists trip_title text not null default '';

create table if not exists public.atlas_share_links (
  id uuid primary key default gen_random_uuid(),
  trip_id uuid not null references public.atlas_trips(id) on delete cascade,
  token uuid not null unique default gen_random_uuid(),
  role text not null check (role in ('viewer', 'editor')),
  active boolean not null default true,
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  unique (trip_id, role)
);

create or replace function public.atlas_set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists atlas_trips_set_updated_at on public.atlas_trips;
create trigger atlas_trips_set_updated_at
before update on public.atlas_trips
for each row execute function public.atlas_set_updated_at();

create or replace function public.atlas_can_access_trip(target_trip uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.atlas_trips t
    where t.id = target_trip and t.owner_id = auth.uid()
  ) or exists (
    select 1 from public.atlas_trip_members m
    where m.trip_id = target_trip and m.user_id = auth.uid()
  );
$$;

create or replace function public.atlas_can_edit_trip(target_trip uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.atlas_trips t
    where t.id = target_trip and t.owner_id = auth.uid()
  ) or exists (
    select 1 from public.atlas_trip_members m
    where m.trip_id = target_trip and m.user_id = auth.uid() and m.role = 'editor'
  );
$$;

create or replace function public.atlas_accept_invite(invite_uuid uuid)
returns uuid language plpgsql security definer set search_path = public as $$
declare
  invitation public.atlas_trip_invites%rowtype;
begin
  select * into invitation from public.atlas_trip_invites
  where id = invite_uuid
    and status = 'pending'
    and lower(email) = lower(coalesce(auth.jwt()->>'email', ''))
  for update;

  if not found then
    raise exception 'This invitation is not available for the signed-in account';
  end if;

  insert into public.atlas_trip_members (trip_id, user_id, role)
  values (invitation.trip_id, auth.uid(), invitation.role)
  on conflict (trip_id, user_id) do update set role = excluded.role;

  update public.atlas_trip_invites set status = 'accepted' where id = invitation.id;
  return invitation.trip_id;
end;
$$;

create or replace function public.atlas_get_share_link(link_token uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  share_link public.atlas_share_links%rowtype;
  trip public.atlas_trips%rowtype;
begin
  select * into share_link from public.atlas_share_links
  where token = link_token and active = true;

  if not found then
    raise exception 'This sharing link is unavailable';
  end if;

  select * into trip from public.atlas_trips where id = share_link.trip_id;
  return jsonb_build_object(
    'share_role', share_link.role,
    'trip', jsonb_build_object(
      'id', trip.id,
      'title', trip.title,
      'destination', trip.destination,
      'dates', trip.dates,
      'start_date', trip.start_date,
      'end_date', trip.end_date,
      'destination_lat', trip.destination_lat,
      'destination_lng', trip.destination_lng,
      'days', trip.days,
      'places', trip.places,
      'transport', trip.transport
    )
  );
end;
$$;

create or replace function public.atlas_join_share_link(link_token uuid)
returns uuid language plpgsql security definer set search_path = public as $$
declare
  share_link public.atlas_share_links%rowtype;
begin
  if auth.uid() is null then
    raise exception 'Sign in is required to join a co-editing link';
  end if;

  select * into share_link from public.atlas_share_links
  where token = link_token and active = true and role = 'editor';

  if not found then
    raise exception 'This co-editing link is unavailable';
  end if;

  insert into public.atlas_trip_members (trip_id, user_id, role)
  values (share_link.trip_id, auth.uid(), 'editor')
  on conflict (trip_id, user_id) do update set role = 'editor';

  return share_link.trip_id;
end;
$$;

grant usage on schema public to anon, authenticated;
grant select, insert, update, delete on public.atlas_trips to authenticated;
grant select, insert, update, delete on public.atlas_trip_members to authenticated;
grant select, insert, update, delete on public.atlas_trip_invites to authenticated;
grant select, insert, update, delete on public.atlas_share_links to authenticated;
revoke all on function public.atlas_accept_invite(uuid) from public;
revoke all on function public.atlas_get_share_link(uuid) from public;
revoke all on function public.atlas_join_share_link(uuid) from public;
grant execute on function public.atlas_accept_invite(uuid) to authenticated;
grant execute on function public.atlas_get_share_link(uuid) to anon, authenticated;
grant execute on function public.atlas_join_share_link(uuid) to authenticated;

alter table public.atlas_trips enable row level security;
alter table public.atlas_trip_members enable row level security;
alter table public.atlas_trip_invites enable row level security;
alter table public.atlas_share_links enable row level security;

drop policy if exists "atlas trips visible to members" on public.atlas_trips;
create policy "atlas trips visible to members" on public.atlas_trips
for select to authenticated using (public.atlas_can_access_trip(id));

drop policy if exists "atlas trip owners create" on public.atlas_trips;
create policy "atlas trip owners create" on public.atlas_trips
for insert to authenticated with check (owner_id = auth.uid());

drop policy if exists "atlas trip editors update" on public.atlas_trips;
create policy "atlas trip editors update" on public.atlas_trips
for update to authenticated using (public.atlas_can_edit_trip(id))
with check (public.atlas_can_edit_trip(id));

drop policy if exists "atlas trip owners delete" on public.atlas_trips;
create policy "atlas trip owners delete" on public.atlas_trips
for delete to authenticated using (owner_id = auth.uid());

drop policy if exists "atlas members visible to trip members" on public.atlas_trip_members;
create policy "atlas members visible to trip members" on public.atlas_trip_members
for select to authenticated using (public.atlas_can_access_trip(trip_id));

drop policy if exists "atlas owners manage members" on public.atlas_trip_members;
create policy "atlas owners manage members" on public.atlas_trip_members
for insert to authenticated with check (
  exists (select 1 from public.atlas_trips t where t.id = trip_id and t.owner_id = auth.uid())
);

drop policy if exists "atlas owners remove members" on public.atlas_trip_members;
create policy "atlas owners remove members" on public.atlas_trip_members
for delete to authenticated using (
  exists (select 1 from public.atlas_trips t where t.id = trip_id and t.owner_id = auth.uid())
);

drop policy if exists "atlas invites visible to sender or recipient" on public.atlas_trip_invites;
create policy "atlas invites visible to sender or recipient" on public.atlas_trip_invites
for select to authenticated using (
  created_by = auth.uid() or lower(email) = lower(coalesce(auth.jwt()->>'email', ''))
);

drop policy if exists "atlas owners create invites" on public.atlas_trip_invites;
create policy "atlas owners create invites" on public.atlas_trip_invites
for insert to authenticated with check (
  created_by = auth.uid() and exists (
    select 1 from public.atlas_trips t where t.id = trip_id and t.owner_id = auth.uid()
  )
);

drop policy if exists "atlas invite recipients accept" on public.atlas_trip_invites;

drop policy if exists "atlas owners revoke invites" on public.atlas_trip_invites;
create policy "atlas owners revoke invites" on public.atlas_trip_invites
for update to authenticated using (created_by = auth.uid()) with check (created_by = auth.uid());

drop policy if exists "atlas owners delete invites" on public.atlas_trip_invites;
create policy "atlas owners delete invites" on public.atlas_trip_invites
for delete to authenticated using (created_by = auth.uid());

drop policy if exists "atlas owners manage share links" on public.atlas_share_links;
create policy "atlas owners manage share links" on public.atlas_share_links
for all to authenticated using (
  exists (select 1 from public.atlas_trips t where t.id = trip_id and t.owner_id = auth.uid())
) with check (
  created_by = auth.uid() and exists (
    select 1 from public.atlas_trips t where t.id = trip_id and t.owner_id = auth.uid()
  )
);

alter table public.atlas_trips replica identity full;
do $$
begin
  alter publication supabase_realtime add table public.atlas_trips;
exception when duplicate_object then null;
end;
$$;
