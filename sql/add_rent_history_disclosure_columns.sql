-- Rent history disclosure (Article 1896 CCQ)
-- ---------------------------------------------
-- When a landlord signs a new tenant in Quebec, the law requires
-- disclosing the lowest rent paid by a previous occupant in the 12
-- months before the new lease starts (or, if the unit was vacant /
-- owner-occupied through that period, the last rent paid and its date).
--
-- These columns are an optional place for a landlord to record that
-- disclosure in Praedium -- for their own records, and so it can be
-- shown to the tenant on their portal if the landlord wants to use
-- Praedium as the way they deliver it. Praedium doesn't require this
-- or generate the official TAL notice form itself.
--
-- Run this once in the Supabase SQL editor.

alter table tenants
  add column if not exists lowest_rent_disclosed_amount integer,
  add column if not exists lowest_rent_disclosure_note text;
