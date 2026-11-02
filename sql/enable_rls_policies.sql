-- ============================================================
-- Praedium: enable Supabase Row Level Security (RLS) + policies
-- ============================================================
-- Run this in the Supabase Dashboard -> SQL Editor -> New query.
--
-- Status as of the last check: RLS is already ON for every table in the
-- public schema. Only `customers` and `properties` have any policies
-- defined (scoped to auth.uid() = user_id, which is correct) -- every
-- other table has RLS on with zero policies, which denies all access by
-- default to anon/authenticated. This script is additive: it uses policy
-- names that don't exist yet, so it won't touch or conflict with the
-- "Customers can ..." policies already in place. It fills in the gaps.
--
-- Casting note: your existing policies compare auth.uid()::text to the
-- owner column cast to ::text, which suggests those id columns may not
-- be native `uuid` type. This script matches that casting throughout so
-- it won't hit a type-mismatch error regardless of the actual column
-- type.
--
-- What this script does NOT change: your backend always connects to
-- Supabase with the service role key, which bypasses RLS entirely by
-- design -- so turning this on doesn't change how the app behaves for
-- anyone using it normally through app.praedium.pro. It only closes the
-- direct-to-Supabase path that exists outside your backend, using the
-- public anon key.
--
-- Safe to re-run: every policy below is dropped and recreated by name,
-- so running this more than once won't error or duplicate anything.

-- ---------- properties ----------
alter table public.properties enable row level security;

drop policy if exists "landlords manage their own properties" on public.properties;
create policy "landlords manage their own properties"
  on public.properties
  for all
  to authenticated
  using (auth.uid()::text = user_id::text)
  with check (auth.uid()::text = user_id::text);

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
      where p.id::text = tenants.property_id::text and p.user_id::text = auth.uid()::text
    )
  )
  with check (
    exists (
      select 1 from public.properties p
      where p.id::text = tenants.property_id::text and p.user_id::text = auth.uid()::text
    )
  );

drop policy if exists "tenants read their own record" on public.tenants;
create policy "tenants read their own record"
  on public.tenants
  for select
  to authenticated
  using (auth_user_id::text = auth.uid()::text);

drop policy if exists "tenants update their own language preference" on public.tenants;
create policy "tenants update their own language preference"
  on public.tenants
  for update
  to authenticated
  using (auth_user_id::text = auth.uid()::text)
  with check (auth_user_id::text = auth.uid()::text);

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
      join public.properties p on p.id::text = t.property_id::text
      where t.id::text = payments.tenant_id::text and p.user_id::text = auth.uid()::text
    )
  )
  with check (
    exists (
      select 1 from public.tenants t
      join public.properties p on p.id::text = t.property_id::text
      where t.id::text = payments.tenant_id::text and p.user_id::text = auth.uid()::text
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
      where t.id::text = payments.tenant_id::text and t.auth_user_id::text = auth.uid()::text
    )
  );

-- ---------- expenses ----------
alter table public.expenses enable row level security;

drop policy if exists "landlords manage their own expenses" on public.expenses;
create policy "landlords manage their own expenses"
  on public.expenses
  for all
  to authenticated
  using (auth.uid()::text = user_id::text)
  with check (auth.uid()::text = user_id::text);

-- ---------- documents ----------
alter table public.documents enable row level security;

drop policy if exists "landlords manage their own documents" on public.documents;
create policy "landlords manage their own documents"
  on public.documents
  for all
  to authenticated
  using (auth.uid()::text = user_id::text)
  with check (auth.uid()::text = user_id::text);

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
      where p.id::text = maintenance_requests.property_id::text and p.user_id::text = auth.uid()::text
    )
  )
  with check (
    exists (
      select 1 from public.properties p
      where p.id::text = maintenance_requests.property_id::text and p.user_id::text = auth.uid()::text
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
      where t.id::text = maintenance_requests.tenant_id::text and t.auth_user_id::text = auth.uid()::text
    )
  )
  with check (
    exists (
      select 1 from public.tenants t
      where t.id::text = maintenance_requests.tenant_id::text and t.auth_user_id::text = auth.uid()::text
    )
  );

-- ---------- vendors ----------
alter table public.vendors enable row level security;

drop policy if exists "landlords manage their own vendors" on public.vendors;
create policy "landlords manage their own vendors"
  on public.vendors
  for all
  to authenticated
  using (auth.uid()::text = user_id::text)
  with check (auth.uid()::text = user_id::text);

-- ---------- customers (billing) ----------
-- Already has "Customers can view/update their own data" policies
-- (SELECT, UPDATE). No change needed there. We deliberately do NOT add
-- an insert/delete policy here -- plan tier, subscription status, and
-- Stripe ids should only ever be written by the backend (service role)
-- or the Stripe webhook, never directly by a logged-in user.
alter table public.customers enable row level security;

-- ---------- sms_messages ----------
alter table public.sms_messages enable row level security;

drop policy if exists "landlords read their own sms history" on public.sms_messages;
create policy "landlords read their own sms history"
  on public.sms_messages
  for select
  to authenticated
  using (auth.uid()::text = user_id::text);

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
