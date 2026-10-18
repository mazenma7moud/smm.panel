-- SMM Panel: Supabase / PostgreSQL schema
-- Run once in Supabase > SQL Editor.

create type order_status as enum ('Pending','Processing','Completed','Partial','Canceled','Refunded','Failed');
create type tx_type as enum ('deposit','charge','refund','adjustment');
create type pay_status as enum ('pending','paid','failed','rejected');

-- ---------- Tables ----------
create table profiles(
  id uuid primary key references auth.users on delete cascade,
  username text,
  role text not null default 'user' check (role in ('user','admin')),
  banned boolean not null default false,
  referral_code text unique default substr(md5(random()::text),1,8),
  referred_by uuid references profiles(id),
  created_at timestamptz not null default now());

create table wallets(
  user_id uuid primary key references profiles(id) on delete cascade,
  balance numeric(14,4) not null default 0 check (balance >= 0),
  updated_at timestamptz not null default now());

create table categories(
  id serial primary key, name text not null,
  sort int not null default 0, active boolean not null default true);

create table providers(
  id serial primary key, name text not null, api_url text not null,
  active boolean not null default true, created_at timestamptz not null default now());

-- API keys live apart from providers; no policy = no client access (service role only)
create table provider_secrets(
  provider_id int primary key references providers(id) on delete cascade,
  api_key text not null);

create table services(
  id serial primary key,
  category_id int references categories(id),
  name text not null, description text,
  price_per_1000 numeric(12,4) not null check (price_per_1000 >= 0),
  min_qty int not null check (min_qty > 0),
  max_qty int not null check (max_qty >= min_qty),
  provider_id int references providers(id),
  provider_service_id text,
  active boolean not null default true,
  created_at timestamptz not null default now());

create table orders(
  id bigint generated always as identity primary key,
  user_id uuid not null references profiles(id),
  service_id int not null references services(id),
  link text not null,
  quantity int not null check (quantity > 0),
  unit_price numeric(12,4) not null,           -- price snapshot at order time
  total numeric(14,4) not null check (total >= 0),
  status order_status not null default 'Pending',
  provider_order_id text, error text,
  idempotency_key text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (user_id, idempotency_key));

create table transactions(
  id bigint generated always as identity primary key,
  user_id uuid not null references profiles(id),
  type tx_type not null,
  amount numeric(14,4) not null,               -- signed
  balance_after numeric(14,4) not null,
  reference text not null unique,              -- blocks duplicate charges/deposits
  reason text, order_id bigint references orders(id),
  created_by uuid references profiles(id),
  created_at timestamptz not null default now());

create table payments(
  id bigint generated always as identity primary key,
  user_id uuid not null references profiles(id),
  method text not null, amount numeric(14,4) not null check (amount > 0),
  note text, status pay_status not null default 'pending',
  gateway_ref text unique, reviewed_by uuid references profiles(id),
  created_at timestamptz not null default now());

create table support_tickets(
  id bigint generated always as identity primary key,
  user_id uuid not null references profiles(id),
  subject text not null,
  status text not null default 'open' check (status in ('open','in_progress','closed')),
  priority text not null default 'normal' check (priority in ('low','normal','high')),
  created_at timestamptz not null default now());

create table ticket_messages(
  id bigint generated always as identity primary key,
  ticket_id bigint not null references support_tickets(id) on delete cascade,
  sender uuid not null references profiles(id),
  is_staff boolean not null default false,
  body text not null, created_at timestamptz not null default now());

create table coupons(
  code text primary key, kind text not null check (kind in ('percent','fixed')),
  value numeric(12,4) not null, max_uses int, used int not null default 0,
  expires_at timestamptz, active boolean not null default true);

create table settings(key text primary key, value jsonb not null, is_public boolean not null default false);

create table audit_logs(
  id bigint generated always as identity primary key,
  actor uuid, action text not null, details jsonb,
  created_at timestamptz not null default now());

create index on orders(user_id, created_at desc);
create index on orders(status);
create index on transactions(user_id, created_at desc);
create index on services(category_id);

insert into settings(key,value,is_public) values
 ('site_name','"smm panel"',true), ('logo','"🌸"',true),
 ('colors','{"ac":"#7c3aed","nv":"#111b4d","bg":"#05060f"}',true);

-- ---------- Helpers ----------
create function is_admin() returns boolean language sql stable security definer set search_path=public as $$
  select exists(select 1 from profiles where id = auth.uid() and role = 'admin' and not banned) $$;

create function handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
begin
  insert into profiles(id, username) values (new.id, coalesce(new.raw_user_meta_data->>'username', split_part(new.email,'@',1)));
  insert into wallets(user_id) values (new.id);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function handle_new_user();

create function touch_updated_at() returns trigger language plpgsql as $$ begin new.updated_at = now(); return new; end $$;
create trigger orders_touch before update on orders for each row execute function touch_updated_at();

-- ---------- Wallet core (internal only) ----------
create function wallet_apply(p_user uuid, p_type tx_type, p_amount numeric, p_ref text, p_reason text,
                             p_order bigint default null, p_by uuid default null)
returns boolean language plpgsql security definer set search_path=public as $$
declare bal numeric;
begin
  select balance into bal from wallets where user_id = p_user for update;   -- row lock
  if not found then raise exception 'no_wallet'; end if;
  if exists (select 1 from transactions where reference = p_ref) then return false; end if;  -- idempotent
  if bal + p_amount < 0 then raise exception 'insufficient_balance'; end if;
  update wallets set balance = bal + p_amount, updated_at = now() where user_id = p_user;
  insert into transactions(user_id,type,amount,balance_after,reference,reason,order_id,created_by)
  values (p_user,p_type,p_amount,bal + p_amount,p_ref,p_reason,p_order,p_by);
  return true;
end $$;
revoke all on function wallet_apply from public, anon, authenticated;

-- ---------- Client-callable functions ----------
create function place_order(p_service int, p_link text, p_qty int, p_key text)
returns bigint language plpgsql security definer set search_path=public as $$
declare s services%rowtype; uid uuid := auth.uid(); oid bigint; tot numeric;
begin
  if uid is null then raise exception 'auth_required'; end if;
  if exists (select 1 from profiles where id = uid and banned) then raise exception 'banned'; end if;
  select id into oid from orders where user_id = uid and idempotency_key = p_key;
  if found then return oid; end if;                                   -- retry-safe
  select * into s from services where id = p_service and active;
  if not found then raise exception 'service_unavailable'; end if;
  if p_qty < s.min_qty or p_qty > s.max_qty then raise exception 'bad_quantity'; end if;
  if p_link !~* '^https?://' then raise exception 'bad_link'; end if;
  tot := round(s.price_per_1000 * p_qty / 1000, 4);
  insert into orders(user_id,service_id,link,quantity,unit_price,total,idempotency_key)
  values (uid,s.id,p_link,p_qty,s.price_per_1000,tot,p_key) returning id into oid;
  perform wallet_apply(uid,'charge',-tot,'order:'||oid,'Order #'||oid,oid);  -- fails => whole order rolls back
  return oid;
end $$;

create function request_deposit(p_method text, p_amount numeric, p_note text default null)
returns bigint language plpgsql security definer set search_path=public as $$
declare pid bigint;
begin
  if auth.uid() is null then raise exception 'auth_required'; end if;
  insert into payments(user_id,method,amount,note) values (auth.uid(),p_method,p_amount,p_note) returning id into pid;
  return pid;
end $$;

-- ---------- Admin-only functions ----------
create function approve_payment(p_id bigint) returns void language plpgsql security definer set search_path=public as $$
declare u uuid; a numeric;
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  update payments set status='paid', reviewed_by=auth.uid() where id=p_id and status='pending' returning user_id, amount into u, a;
  if not found then raise exception 'not_pending'; end if;
  perform wallet_apply(u,'deposit',a,'pay:'||p_id,'Deposit approved',null,auth.uid());
  insert into audit_logs(actor,action,details) values (auth.uid(),'payment_approved',jsonb_build_object('payment',p_id,'amount',a));
end $$;

create function admin_adjust_balance(p_user uuid, p_amount numeric, p_reason text) returns void
language plpgsql security definer set search_path=public as $$
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  if coalesce(trim(p_reason),'') = '' then raise exception 'reason_required'; end if;
  perform wallet_apply(p_user,'adjustment',p_amount,'adj:'||gen_random_uuid(),p_reason,null,auth.uid());
  insert into audit_logs(actor,action,details) values (auth.uid(),'balance_adjust',jsonb_build_object('user',p_user,'amount',p_amount,'reason',p_reason));
end $$;

create function refund_order(p_id bigint, p_status order_status default 'Refunded') returns void
language plpgsql security definer set search_path=public as $$
declare o orders%rowtype;
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  if p_status not in ('Refunded','Canceled') then raise exception 'bad_status'; end if;
  select * into o from orders where id = p_id for update;
  if not found then raise exception 'not_found'; end if;
  if o.status in ('Refunded','Canceled') then raise exception 'already_refunded'; end if;
  update orders set status = p_status where id = p_id;
  perform wallet_apply(o.user_id,'refund',o.total,'refund:'||p_id,'Refund order #'||p_id,p_id,auth.uid());
  insert into audit_logs(actor,action,details) values (auth.uid(),'order_refunded',jsonb_build_object('order',p_id,'total',o.total));
end $$;

create function admin_set_user(p_user uuid, p_banned boolean, p_role text) returns void
language plpgsql security definer set search_path=public as $$
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  update profiles set banned = p_banned, role = p_role where id = p_user;
  insert into audit_logs(actor,action,details) values (auth.uid(),'user_updated',jsonb_build_object('user',p_user,'banned',p_banned,'role',p_role));
end $$;

revoke all on function place_order, request_deposit, approve_payment, admin_adjust_balance, refund_order, admin_set_user from public, anon;
grant execute on function place_order, request_deposit, approve_payment, admin_adjust_balance, refund_order, admin_set_user to authenticated;

-- ---------- Row Level Security ----------
do $$ declare t text; begin
  foreach t in array array['profiles','wallets','categories','providers','provider_secrets','services','orders','transactions',
                           'payments','support_tickets','ticket_messages','coupons','settings','audit_logs'] loop
    execute format('alter table %I enable row level security', t);
  end loop;
  -- admins manage these directly
  foreach t in array array['categories','providers','services','coupons','settings','support_tickets','ticket_messages'] loop
    execute format('create policy admin_all on %I for all using (is_admin()) with check (is_admin())', t);
  end loop;
  -- admins read-only (writes only through functions)
  foreach t in array array['profiles','wallets','transactions','payments','audit_logs','orders'] loop
    execute format('create policy admin_read on %I for select using (is_admin())', t);
  end loop;
end $$;

create policy own_profile on profiles for select using (id = auth.uid());
create policy own_profile_upd on profiles for update using (id = auth.uid()) with check (id = auth.uid());
create policy own_wallet on wallets for select using (user_id = auth.uid());
create policy own_tx on transactions for select using (user_id = auth.uid());
create policy own_orders on orders for select using (user_id = auth.uid());
create policy admin_orders_upd on orders for update using (is_admin()) with check (is_admin());
create policy own_payments on payments for select using (user_id = auth.uid());
create policy own_tickets on support_tickets for select using (user_id = auth.uid());
create policy own_tickets_ins on support_tickets for insert with check (user_id = auth.uid());
create policy own_msgs on ticket_messages for select using (exists (select 1 from support_tickets t where t.id = ticket_id and t.user_id = auth.uid()));
create policy own_msgs_ins on ticket_messages for insert with check (
  sender = auth.uid() and not is_staff and exists (select 1 from support_tickets t where t.id = ticket_id and t.user_id = auth.uid()));
create policy public_cats on categories for select using (active);
create policy public_settings on settings for select using (is_public);

-- Column-level locks: users can't touch money, roles or order totals
revoke insert, update, delete on wallets, transactions, payments, audit_logs from anon, authenticated;
revoke insert, update, delete on orders from anon, authenticated;
grant update (status, provider_order_id, error) on orders to authenticated;   -- still needs admin policy
revoke update on profiles from anon, authenticated;
grant update (username) on profiles to authenticated;
revoke all on provider_secrets from anon, authenticated;

-- Safe public catalog (hides provider ids)
create view public_services as
  select id, category_id, name, description, price_per_1000, min_qty, max_qty from services where active;
grant select on public_services to anon, authenticated;
