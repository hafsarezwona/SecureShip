create table public.workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 120),
  created_at timestamptz not null default now()
);

create table public.workspace_members (
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'owner' check (role in ('owner','admin','member')),
  created_at timestamptz not null default now(),
  primary key (workspace_id, user_id)
);

insert into public.profiles (id, full_name)
select u.id, nullif(u.raw_user_meta_data ->> 'full_name', '') from auth.users u
on conflict (id) do nothing;

insert into public.workspaces (id, name)
select p.id, coalesce(nullif(p.full_name, ''), 'Personal') || '''s workspace'
from public.profiles p;

insert into public.workspace_members (workspace_id, user_id)
select id, id from public.workspaces;

create table public.workspace_subscriptions (
  workspace_id uuid primary key references public.workspaces(id) on delete cascade,
  plan text not null default 'free' check (plan in ('free','premium')),
  status text not null default 'active' check (status in ('active','pending','past_due','canceled','expired')),
  provider text,
  provider_subscription_id text,
  current_period_start timestamptz not null default now(),
  current_period_end timestamptz,
  cancel_at_period_end boolean not null default false,
  updated_at timestamptz not null default now()
);

insert into public.workspace_subscriptions (workspace_id) select id from public.workspaces;

create table public.payment_orders (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  created_by uuid not null references auth.users(id),
  provider text not null default 'sslcommerz',
  tran_id text not null unique,
  amount numeric(12,2) not null check (amount > 0),
  currency text not null default 'BDT' check (currency = 'BDT'),
  status text not null default 'pending' check (status in ('pending','paid','failed','canceled')),
  provider_val_id text,
  created_at timestamptz not null default now(),
  paid_at timestamptz
);

alter table public.projects add column workspace_id uuid references public.workspaces(id);
update public.projects set workspace_id = user_id;
alter table public.projects alter column workspace_id set not null;
alter table public.scans add column workspace_id uuid references public.workspaces(id);
update public.scans s set workspace_id = p.workspace_id from public.projects p where p.id = s.project_id;
alter table public.scans alter column workspace_id set not null;
create index projects_workspace_created_idx on public.projects(workspace_id, created_at desc);
create index scans_workspace_created_idx on public.scans(workspace_id, created_at desc);
create index payment_orders_workspace_created_idx on public.payment_orders(workspace_id, created_at desc);
create unique index payment_orders_one_pending_workspace_idx on public.payment_orders(workspace_id) where status = 'pending';

alter table public.workspaces enable row level security;
alter table public.workspace_members enable row level security;
alter table public.workspace_subscriptions enable row level security;
alter table public.payment_orders enable row level security;

create policy workspace_members_read_own on public.workspace_members for select using (user_id = (select auth.uid()));
create policy workspaces_read_member on public.workspaces for select using (exists (
  select 1 from public.workspace_members m where m.workspace_id = id and m.user_id = (select auth.uid())
));
create policy workspace_subscriptions_read_member on public.workspace_subscriptions for select using (exists (
  select 1 from public.workspace_members m where m.workspace_id = workspace_subscriptions.workspace_id and m.user_id = (select auth.uid())
));
create policy payment_orders_read_member on public.payment_orders for select using (exists (
  select 1 from public.workspace_members m where m.workspace_id = payment_orders.workspace_id and m.user_id = (select auth.uid())
));

drop policy if exists projects_own on public.projects;
create policy projects_own on public.projects for all using (user_id = (select auth.uid())) with check (
  user_id = (select auth.uid()) and exists (
    select 1 from public.workspace_members m where m.workspace_id = projects.workspace_id and m.user_id = (select auth.uid())
  )
);

create or replace function public.complete_payment_order(p_tran_id text, p_val_id text)
returns boolean language plpgsql security definer set search_path = '' as $$
declare payment public.payment_orders%rowtype;
declare started_at timestamptz;
begin
  select * into payment from public.payment_orders where tran_id = p_tran_id for update;
  if not found then return false; end if;
  if payment.status = 'paid' then return true; end if;
  started_at := greatest(now(), coalesce((select current_period_end from public.workspace_subscriptions where workspace_id = payment.workspace_id), now()));
  update public.payment_orders set status = 'paid', provider_val_id = p_val_id, paid_at = now() where id = payment.id;
  insert into public.workspace_subscriptions (workspace_id, plan, status, provider, current_period_start, current_period_end, cancel_at_period_end, updated_at)
  values (payment.workspace_id, 'premium', 'active', 'sslcommerz', started_at, started_at + interval '30 days', false, now())
  on conflict (workspace_id) do update set plan = 'premium', status = 'active', provider = 'sslcommerz', current_period_start = excluded.current_period_start, current_period_end = excluded.current_period_end, cancel_at_period_end = false, updated_at = now();
  return true;
end;
$$;

create or replace function public.fail_payment_order(p_tran_id text)
returns void language sql security definer set search_path = '' as $$
  update public.payment_orders set status = 'failed' where tran_id = p_tran_id and status = 'pending';
$$;

create or replace function public.cancel_workspace_subscription(p_workspace_id uuid)
returns boolean language plpgsql security definer set search_path = '' as $$
begin
  update public.workspace_subscriptions set cancel_at_period_end = true, updated_at = now()
  where workspace_id = p_workspace_id and plan = 'premium' and status = 'active' and current_period_end > now();
  return found;
end;
$$;

revoke all on function public.complete_payment_order(text, text) from public, anon, authenticated;
revoke all on function public.fail_payment_order(text) from public, anon, authenticated;
revoke all on function public.cancel_workspace_subscription(uuid) from public, anon, authenticated;
grant execute on function public.complete_payment_order(text, text), public.fail_payment_order(text), public.cancel_workspace_subscription(uuid) to service_role;

create or replace function public.create_profile_for_user()
returns trigger language plpgsql security definer set search_path = '' as $$
declare workspace_id uuid;
begin
  insert into public.profiles (id, full_name)
  values (new.id, nullif(new.raw_user_meta_data ->> 'full_name', ''))
  on conflict (id) do nothing;
  insert into public.workspaces (name)
  values (coalesce(nullif(new.raw_user_meta_data ->> 'full_name', ''), 'Personal') || '''s workspace')
  returning id into workspace_id;
  insert into public.workspace_members (workspace_id, user_id) values (workspace_id, new.id);
  insert into public.workspace_subscriptions (workspace_id) values (workspace_id);
  return new;
end;
$$;
