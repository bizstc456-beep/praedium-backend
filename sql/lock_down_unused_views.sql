-- ============================================================
-- Praedium: lock down unused summary views
-- ============================================================
-- Run this in the Supabase Dashboard -> SQL Editor -> New query.
--
-- monthly_payment_summary, property_occupancy_summary, and
-- tenant_status_summary are views owned by `postgres`, not marked
-- security_invoker. That means Postgres runs them with the view
-- owner's own privileges, not the querying role's -- so even with RLS
-- now enabled on every underlying table, these three views ignore all
-- of it and would return every landlord's data to anyone who queries
-- them, including a plain anon-key request to Supabase's public REST
-- API with no login at all.
--
-- None of the three are referenced anywhere in server.js -- the app
-- doesn't use them. So instead of trying to rewrite them to respect
-- RLS, this just removes the public API's ability to serve them at
-- all, which fully closes the hole.
--
-- Safe to re-run.

revoke all privileges on public.monthly_payment_summary from anon, authenticated;
revoke all privileges on public.property_occupancy_summary from anon, authenticated;
revoke all privileges on public.tenant_status_summary from anon, authenticated;

-- Belt-and-suspenders, in case Postgres version supports it (15+) and
-- someone re-grants access to these views later without realizing why
-- that's risky: make them respect the querying role's own RLS instead
-- of running as the view owner. Harmless to attempt even if the app
-- never ends up using these views.
alter view public.monthly_payment_summary set (security_invoker = true);
alter view public.property_occupancy_summary set (security_invoker = true);
alter view public.tenant_status_summary set (security_invoker = true);
