-- Account deletion: email + 7-day undo window
-- ---------------------------------------------
-- deletion_cancel_token: random token emailed to the account holder as a
--   one-click "cancel this" link. Null once there's no pending request.
-- deletion_grace_alert_sent: flips to true once the 7-day grace period has
--   passed uncancelled and the owner has been re-alerted, so that alert
--   doesn't fire again every day for the same request.
--
-- Run this once in the Supabase SQL editor.

alter table customers
  add column if not exists deletion_cancel_token text,
  add column if not exists deletion_grace_alert_sent boolean not null default false;

-- Lets the cancel-deletion endpoint look a request up by token in O(1),
-- and guarantees two pending requests can never collide on the same token.
create unique index if not exists customers_deletion_cancel_token_idx
  on customers (deletion_cancel_token)
  where deletion_cancel_token is not null;
