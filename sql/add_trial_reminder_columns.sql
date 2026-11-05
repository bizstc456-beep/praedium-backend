alter table customers
  add column if not exists stripe_trial_end timestamptz,
  add column if not exists trial_ending_reminder_sent boolean not null default false;
