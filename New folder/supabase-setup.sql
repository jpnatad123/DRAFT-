create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null,
  email text not null unique,
  role text not null default 'Student' check (role in ('Student', 'Faculty', 'Staff', 'Administrator')),
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.resources (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles(id) on delete cascade,
  owner_name text not null,
  contact_email text not null,
  title text not null,
  category text not null,
  sharing_type text not null check (sharing_type in ('Free', 'Donate', 'Reuse', 'Swap')),
  condition text not null check (condition in ('Like new', 'Good', 'Fair')),
  description text not null default '',
  image_url text not null default '',
  weight_kg numeric not null default 0.4 check (weight_kg >= 0),
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected', 'withdrawn')),
  reviewed_by uuid references public.profiles(id),
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists resources_status_created_idx on public.resources (status, created_at desc);
create index if not exists resources_owner_created_idx on public.resources (owner_id, created_at desc);

create or replace function public.current_app_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select role from public.profiles where id = auth.uid() and is_active = true;
$$;

create or replace function public.is_campus_staff()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(public.current_app_role() in ('Staff', 'Administrator'), false);
$$;

create or replace function public.is_campus_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(public.current_app_role() = 'Administrator', false);
$$;

create or replace function public.create_profile_for_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  requested_role text;
  safe_role text;
  profile_name text;
begin
  requested_role := new.raw_user_meta_data ->> 'role';
  safe_role := case when requested_role = 'Faculty' then 'Faculty' else 'Student' end;
  profile_name := nullif(trim(new.raw_user_meta_data ->> 'full_name'), '');

  insert into public.profiles (id, full_name, email, role)
  values (
    new.id,
    coalesce(profile_name, split_part(coalesce(new.email, ''), '@', 1), 'Campus member'),
    lower(new.email),
    safe_role
  );
  return new;
end;
$$;

drop trigger if exists create_profile_after_signup on auth.users;
create trigger create_profile_after_signup
after insert on auth.users
for each row execute procedure public.create_profile_for_new_user();

create or replace function public.set_account_access(target_user_id uuid, new_role text, new_is_active boolean)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if public.current_app_role() is distinct from 'Administrator' then
    raise exception 'Administrator access required';
  end if;
  if new_role is null or new_role not in ('Student', 'Faculty', 'Staff', 'Administrator') then
    raise exception 'Invalid account role';
  end if;
  update public.profiles
  set role = new_role, is_active = new_is_active
  where id = target_user_id;
end;
$$;

create or replace function public.set_resource_owner_fields()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  select full_name, email into new.owner_name, new.contact_email
  from public.profiles
  where id = auth.uid() and is_active = true;
  if new.owner_name is null or new.contact_email is null then
    raise exception 'An active campus account is required to share resources';
  end if;
  return new;
end;
$$;

drop trigger if exists set_resource_owner_fields_before_insert on public.resources;
create trigger set_resource_owner_fields_before_insert
before insert on public.resources
for each row execute procedure public.set_resource_owner_fields();

create or replace function public.get_resource_contact(target_resource_id uuid)
returns text
language sql
stable
security definer
set search_path = public
as $$
  select r.contact_email
  from public.resources r
  join public.profiles p on p.id = r.owner_id and p.is_active = true
  where r.id = target_resource_id
    and (r.status = 'approved' or r.owner_id = auth.uid() or public.is_campus_staff());
$$;

create or replace function public.guard_resource_moderation()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.owner_id is distinct from old.owner_id then
    raise exception 'Resource ownership cannot be changed';
  end if;
  select full_name, email into new.owner_name, new.contact_email
  from public.profiles
  where id = new.owner_id;
  if public.current_app_role() is distinct from 'Staff'
    and public.current_app_role() is distinct from 'Administrator'
    and (new.status is distinct from old.status
      or new.reviewed_by is distinct from old.reviewed_by
      or new.reviewed_at is distinct from old.reviewed_at) then
    raise exception 'Staff review is required to change resource status';
  end if;
  return new;
end;
$$;

drop trigger if exists guard_resource_moderation_before_update on public.resources;
create trigger guard_resource_moderation_before_update
before update on public.resources
for each row execute procedure public.guard_resource_moderation();

alter table public.profiles enable row level security;
alter table public.resources enable row level security;

revoke all on public.profiles from anon, authenticated;
revoke all on public.resources from anon, authenticated;
revoke all on function public.set_account_access(uuid, text, boolean) from public, anon;
revoke all on function public.get_resource_contact(uuid) from public, anon;
grant select on public.profiles to authenticated;
grant update (full_name) on public.profiles to authenticated;
grant select, insert, update, delete on public.resources to authenticated;
grant execute on function public.set_account_access(uuid, text, boolean) to authenticated;
grant execute on function public.get_resource_contact(uuid) to authenticated;

drop policy if exists "Profiles visible to account or staff" on public.profiles;
create policy "Profiles visible to account or staff"
on public.profiles for select to authenticated
using (id = auth.uid() or public.is_campus_admin());

drop policy if exists "Members update their own name" on public.profiles;
create policy "Members update their own name"
on public.profiles for update to authenticated
using (id = auth.uid() and is_active = true)
with check (id = auth.uid());

drop policy if exists "Approved resources visible to campus" on public.resources;
create policy "Approved resources visible to campus"
on public.resources for select to authenticated
using ((status = 'approved' and public.current_app_role() is not null)
  or (owner_id = auth.uid() and public.current_app_role() is not null)
  or public.is_campus_staff());

drop policy if exists "Members submit their own pending resources" on public.resources;
create policy "Members submit their own pending resources"
on public.resources for insert to authenticated
with check (owner_id = auth.uid() and public.current_app_role() in ('Student', 'Faculty', 'Staff', 'Administrator') and status = 'pending');

drop policy if exists "Owners and staff update resources" on public.resources;
create policy "Owners and staff update resources"
on public.resources for update to authenticated
using ((owner_id = auth.uid() and public.current_app_role() is not null) or public.is_campus_staff())
with check ((owner_id = auth.uid() and public.current_app_role() is not null) or public.is_campus_staff());

drop policy if exists "Owners withdraw pending or staff remove resources" on public.resources;
create policy "Owners withdraw pending or staff remove resources"
on public.resources for delete to authenticated
using ((owner_id = auth.uid() and status = 'pending' and public.current_app_role() is not null) or public.is_campus_staff());
