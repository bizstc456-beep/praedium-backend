alter table maintenance_requests
  add column if not exists vendor_id uuid references vendors(id) on delete set null;
