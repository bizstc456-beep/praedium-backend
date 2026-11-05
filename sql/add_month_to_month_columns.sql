alter table tenants
  add column if not exists is_month_to_month boolean not null default false,
  add column if not exists planned_rent_change_date date;
