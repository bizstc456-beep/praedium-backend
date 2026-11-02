-- ============================================================
-- Praedium: enable Supabase Row Level Security (RLS) + policies
-- ============================================================
-- Run this in the Supabase Dashboard -> SQL Editor -> New query.
--
-- STEP 0 -- run this FIRST, by itself, to see where you currently stand:
--
--   select tablename, rowsecurity
--   from pg_tables
--   where schemaname = 'public'
--   order by tablename;
--
-- rowsecurity = false on any table below means that table currently has
-- ZERO protection against being read directly through Supabase's
-- auto-generated REST API using the anon key -- and that key is public,
-- shipped inside your frontend's JS bundle for anyone to read out of the
-- browser's network tab or the built files. That's a different, more
-- urgent risk than anything in server.js: it has nothing to do with your
-- backend's ownership checks, and no amount of fixing server.js closes
-- it, because it bypasses server.js entirely. If anything comes back
-- false here, this is worth running today.
--
-- What this script does NOT change: your backend always connects to
-- Supabase with the service role key, which bypasses RLS entirely by
-- design -- so turning this on doesn't change how the app behaves for
-- anyone using it normally through app.praedium.pro. It only closes the
-- direct-to-Supabase path that exists outside your backend.
--
-- Safe to re-run: every policy is dropped and recreated, so running this
-- more than once won't error or duplicate anything.

-- ---------- properties ----------
alter table public.properties enable row level security;

drop policy if exists "landlords manage their own properties" on public.properties;
create policy "landlords manage their own properties"
  on public.properties
  for all
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- ---------- tenants ----------
alter table public.tenants enable row level security;

drop policy if exists "landlords manage tenants on their properties" on public.tenants;
create policy "landlords manage tenants on their properties"
  on public.tenants
  for all
  to authenticated
  using (
    exists (
      select 1 from public.properties p
      where p.id = tenants.property_id and p.user_id = auth.uid()
    )
  )
  with check (
    exists (
      select 1 from public.properties p
      where p.id = tenants.property_id and p.user_id = auth.uid()
    )
  );

drop policy if exists "tenants read their own record" on public.tenants;
create policy "tenants read their own record"
  on public.tenants
  for select
  to authenticated
  using (auth_user_id = auth.uid());

drop policy if exists "tenants update their own language preference" on public.tenants;
create policy "tenants update their own language preference"
  on public.tenants
  for update
  to authenticated
  using (auth_user_id = auth.uid())
  with check (auth_user_id = auth.uid());

-- ---------- payments ----------
alter table public.payments enable row level security;

drop policy if exists "landlords manage payments for their tenants" on public.payments;
create policy "landlords manage payments for their tenants"
  on public.payments
  for all
  to authenticated
  using (
    exists (
      select 1 from public.tenants t
      join public.properties p on p.id = t.property_id
      where t.id = payments.tenant_id and p.user_id = auth.uid()
    )
  )
  with check (
    exists (
      select 1 from public.tenants t
      join public.properties p on p.id = t.property_id
      where t.id = payments.tenant_id and p.user_id = auth.uid()
    )
  );

drop policy if exists "tenants read their own payments" on public.payments;
create policy "tenants read their own payments"
  on public.payments
  for select
  to authenticated
  using (
    exists (
      select 1 from public.tenants t
      where t.id = payments.tenant_id and t.auth_user_id = auth.uid()
    )
  );

-- ---------- expenses ----------
alter table public.expenses enable row level security;

drop policy if exists "landlords manage their own expenses" on public.expenses;
create policy "landlords manage their own expenses"
  on public.expenses
  for all
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- ---------- documents ----------
alter table public.documents enable row level security;

drop policy if exists "landlords manage their own documents" on public.documents;
create policy "landlords manage their own documents"
  on public.documents
  for all
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- No tenant policy here on purpose: the tenant portal (v1) doesn't give
-- tenants a documents view at all -- only lease info, payments, and
-- maintenance requests. Add a tenant-read policy here only if/when that
-- changes.

-- ---------- maintenance_requests ----------
alter table public.maintenance_requests enable row level security;

drop policy if exists "landlords manage requests on their properties" on public.maintenance_requests;
create policy "landlords manage requests on their properties"
  on public.maintenance_requests
  for all
  to authenticated
  using (
    exists (
      select 1 from public.properties p
      where p.id = maintenance_requests.property_id and p.user_id = auth.uid()
    )
  )
  with check (
    exists (
      select 1 from public.properties p
      where p.id = maintenance_requests.property_id and p.user_id = auth.uid()
    )
  );

drop policy if exists "tenants manage their own requests" on public.maintenance_requests;
create policy "tenants manage their own requests"
  on public.maintenance_requests
  for all
  to authenticated
  using (
    exists (
      select 1 from public.tenants t
      where t.id = maintenance_requests.tenant_id and t.auth_user_id = auth.uid()
    )
  )
  with check (
    exists (
      select 1 from public.tenants t
      where t.id = maintenance_requests.tenant_id and t.auth_user_id = auth.uid()
    )
  );

-- ---------- vendors ----------
alter table public.vendors enable row level security;

drop policy if exists "landlords manage their own vendors" on public.vendors;
create policy "landlords manage their own vendors"
  on public.vendors
  for all
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- ---------- customers (billing) ----------
alter table public.customers enable row level security;

drop policy if exists "landlords read their own billing record" on public.customers;
create policy "landlords read their own billing record"
  on public.customers
  for select
  to authenticated
  using (user_id = auth.uid());

-- No insert/update/delete policy here on purpose: plan tier, subscription
-- status, and Stripe ids are only ever written by the backend (service
-- role) or the Stripe webhook, never directly by a logged-in user.

-- ---------- sms_messages ----------
alter table public.sms_messages enable row level security;

drop policy if exists "landlords read their own sms history" on public.sms_messages;
create policy "landlords read their own sms history"
  on public.sms_messages
  for select
  to authenticated
  using (user_id = auth.uid());

-- ---------- sms_templates ----------
-- Shared read-only reference data (canned message templates), not
-- per-user -- matches server.js's own comment on this route.
alter table public.sms_templates enable row level security;

drop policy if exists "any logged-in user can read sms templates" on public.sms_templates;
create policy "any logged-in user can read sms templates"
  on public.sms_templates
  for select
  to authenticated
  using (true);
