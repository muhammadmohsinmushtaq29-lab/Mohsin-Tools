-- Mohsin Tools admin backend (Supabase / Postgres). Run once in Supabase > SQL Editor.
-- Roles: admin, editor, user. All access is enforced by Row Level Security, not by the frontend.

create table public.profiles(
  id uuid primary key references auth.users on delete cascade,
  email text, display_name text,
  role text not null default 'user' check (role in ('admin','editor','user')),
  status text not null default 'active' check (status in ('active','suspended')),
  created_at timestamptz not null default now());

create or replace function public.role_of(uid uuid) returns text language sql stable security definer set search_path=public as
$$ select role from profiles where id=uid and status='active' $$;
create or replace function public.is_admin() returns boolean language sql stable as $$ select coalesce(public.role_of(auth.uid())='admin',false) $$;
create or replace function public.is_editor() returns boolean language sql stable as $$ select coalesce(public.role_of(auth.uid()) in ('admin','editor'),false) $$;

create or replace function public.on_signup() returns trigger language plpgsql security definer set search_path=public as $$
begin insert into profiles(id,email,display_name) values(new.id,new.email,coalesce(new.raw_user_meta_data->>'name',split_part(new.email,'@',1))); return new; end $$;
create trigger t_signup after insert on auth.users for each row execute function public.on_signup();

-- Block privilege escalation: only admins may change role/status.
create or replace function public.guard_profile() returns trigger language plpgsql as $$
begin
  if (new.role<>old.role or new.status<>old.status or new.id<>old.id) and not public.is_admin() then raise exception 'Only an admin can change role or status'; end if;
  return new; end $$;
create trigger t_guard before update on public.profiles for each row execute function public.guard_profile();

create table public.site_settings(key text primary key, value jsonb not null, updated_by uuid, updated_at timestamptz default now());
create table public.tools(id text primary key, name text not null, icon text, category text, description text,
  enabled boolean default true, hidden boolean default false, premium boolean default false, sort int default 0,
  options jsonb default '{}'::jsonb, updated_at timestamptz default now());
create table public.pages(id uuid primary key default gen_random_uuid(), slug text unique not null check (slug ~ '^[a-z0-9-]{1,80}$'),
  title text not null, body text, status text default 'draft' check (status in ('draft','published')), publish_at timestamptz,
  updated_by uuid, updated_at timestamptz default now());
create table public.messages(id uuid primary key default gen_random_uuid(), name text check (length(name)<=120), email text check (length(email)<=200),
  body text not null check (length(body) between 1 and 5000), created_at timestamptz default now(), handled boolean default false);
create table public.revisions(id bigserial primary key, content_type text, content_id text, previous jsonb, changed_by uuid, changed_at timestamptz default now());
create table public.audit_log(id bigserial primary key, actor uuid, action text, target text, detail jsonb, at timestamptz default now());

create or replace function public.track() returns trigger language plpgsql security definer set search_path=public as $$
declare k text;
begin
  k:=coalesce((to_jsonb(coalesce(new,old))->>'id'),(to_jsonb(coalesce(new,old))->>'key'));
  if tg_op in ('UPDATE','DELETE') then insert into revisions(content_type,content_id,previous,changed_by) values(tg_table_name,k,to_jsonb(old),auth.uid()); end if;
  insert into audit_log(actor,action,target,detail) values(auth.uid(),tg_op,tg_table_name||':'||k,case when tg_op='DELETE' then to_jsonb(old) else null end);
  return coalesce(new,old); end $$;
create trigger t_set after insert or update or delete on public.site_settings for each row execute function public.track();
create trigger t_tools after insert or update or delete on public.tools for each row execute function public.track();
create trigger t_pages after insert or update or delete on public.pages for each row execute function public.track();
create trigger t_prof after update on public.profiles for each row when (old.role is distinct from new.role or old.status is distinct from new.status) execute function public.track();

alter table public.profiles enable row level security; alter table public.site_settings enable row level security; alter table public.tools enable row level security;
alter table public.pages enable row level security; alter table public.messages enable row level security; alter table public.revisions enable row level security; alter table public.audit_log enable row level security;

create policy p_self on profiles for select using (id=auth.uid() or public.is_admin());
create policy p_upd_self on profiles for update using (id=auth.uid() or public.is_admin());
create policy p_del on profiles for delete using (public.is_admin());
create policy s_read on site_settings for select using (true);
create policy s_write on site_settings for all using (public.is_editor()) with check (public.is_editor());
create policy t_read on tools for select using (true);
create policy t_write on tools for all using (public.is_editor()) with check (public.is_editor());
create policy g_read on pages for select using ((status='published' and (publish_at is null or publish_at<=now())) or public.is_editor());
create policy g_write on pages for all using (public.is_editor()) with check (public.is_editor());
create policy m_ins on messages for insert with check (true);
create policy m_read on messages for select using (public.is_admin());
create policy m_upd on messages for update using (public.is_admin());
create policy r_read on revisions for select using (public.is_editor());
create policy a_read on audit_log for select using (public.is_admin());
-- No insert/update/delete policies on revisions or audit_log: only the security-definer trigger writes them.

insert into storage.buckets(id,name,public) values('media','media',true) on conflict do nothing;
create policy media_write on storage.objects for insert with check (bucket_id='media' and public.is_editor());
create policy media_del on storage.objects for delete using (bucket_id='media' and public.is_editor());

-- FIRST ADMIN: sign up on the site, then run (replace the email):
-- update public.profiles set role='admin' where email='you@example.com';
