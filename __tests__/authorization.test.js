// Regression safety net for the app's whole authorization model.
//
// Praedium doesn't use Supabase row-level security to isolate landlords
// and tenants from each other -- the backend always talks to Supabase with
// the service role key, which bypasses RLS entirely. Instead, every route
// below does its own ownership check by hand: load the resource, compare
// its owning landlord (or, for the tenant portal, the session's own
// linked tenant row) against the logged-in user, and reject if they don't
// match. That pattern works today (verified by hand, route by route), but
// nothing stops a *future* route from forgetting to paste it in -- there's
// no database-level backstop here the way RLS would give you.
//
// This file is that backstop, moved into CI: for every ownership-sensitive
// route, it plays the attacker -- a second, unrelated landlord (or a user
// with no tenant portal account) -- and asserts the route still says no.
// A route that starts skipping its ownership check will fail a test here
// instead of silently shipping a data leak.

process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test_secret';
process.env.OWNER_PHONE_NUMBER = '+15145551234';
process.env.SENTRY_DSN = '';
process.env.ADMIN_EMAILS = 'admin@example.com';

jest.mock('stripe', () => {
  const mockStripeClient = {
    checkout: { sessions: { create: jest.fn() } },
    webhooks: { constructEvent: jest.fn() },
    invoices: { list: jest.fn() },
  };
  return jest.fn(() => mockStripeClient);
});

jest.mock('@supabase/supabase-js', () => {
  const mockSupabaseClient = {
    auth: { getUser: jest.fn(), admin: { inviteUserByEmail: jest.fn(), listUsers: jest.fn() } },
    from: jest.fn(),
    storage: { from: jest.fn(() => ({ remove: jest.fn(), upload: jest.fn(), createSignedUrl: jest.fn() })) },
  };
  return { createClient: jest.fn(() => mockSupabaseClient) };
});

jest.mock('twilio', () => {
  const mockTwilioClient = { messages: { create: jest.fn() } };
  const twilioFn = jest.fn(() => mockTwilioClient);
  twilioFn.validateRequest = jest.fn(() => true);
  return twilioFn;
});

const request = require('supertest');
const app = require('../server');
const { createClient } = require('@supabase/supabase-js');

const supabaseMock = createClient();

// Same chain-builder pattern as the rest of this suite (account.test.js,
// checkout.test.js): every query method returns the builder itself, and
// .single()/.then() both resolve to the same fixed result, regardless of
// which .eq(...) filters were chained on along the way. That's exactly
// what we want here -- these tests don't care *which* id a route queried
// with, only that it correctly recognizes the row it got back as belonging
// to someone else.
function makeQueryResult(result) {
  const builder = {};
  ['select', 'update', 'insert', 'delete', 'eq', 'in', 'or', 'order', 'limit', 'gte'].forEach((method) => {
    builder[method] = jest.fn(() => builder);
  });
  builder.single = jest.fn(() => Promise.resolve(result));
  builder.maybeSingle = jest.fn(() => Promise.resolve(result));
  builder.then = (onFulfilled, onRejected) => Promise.resolve(result).then(onFulfilled, onRejected);
  return builder;
}

const OWNER_ID = 'owner_landlord_1';
const ATTACKER_ID = 'attacker_landlord_2';

function mockAsAttacker() {
  supabaseMock.auth.getUser.mockResolvedValue({
    data: { user: { id: ATTACKER_ID, email: 'attacker@example.com' } },
    error: null,
  });
}

function mockAsUserWithNoTenantAccount() {
  supabaseMock.auth.getUser.mockResolvedValue({
    data: { user: { id: ATTACKER_ID, email: 'attacker@example.com' } },
    error: null,
  });
}

// Every resource an attacking landlord might try to reach by guessing an
// id, all belonging to the OTHER (victim) landlord. Every ownership-check
// route in server.js resolves ownership through one of these tables, so
// one fixture map is enough to make every route's lookup chain land on
// "this belongs to OWNER_ID, not you."
function mockVictimOwnedResources() {
  const fixtures = {
    properties: { id: 'property_1', user_id: OWNER_ID, address: '1 Victim St', property_type: 'duplex' },
    tenants: { id: 'tenant_1', property_id: 'property_1', name: 'Victim Tenant', phone: '+15145550001', email: 'tenant@example.com', auth_user_id: null },
    expenses: { id: 'expense_1', user_id: OWNER_ID },
    vendors: { id: 'vendor_1', user_id: OWNER_ID },
    documents: { id: 'document_1', user_id: OWNER_ID, storage_path: 'owner/doc.pdf', tenant_id: 'tenant_1' },
    maintenance_requests: { id: 'request_1', property_id: 'property_1' },
    customers: { id: 'customer_1', user_id: OWNER_ID, stripe_customer_id: 'cus_victim' },
  };
  supabaseMock.from.mockImplementation((table) =>
    makeQueryResult({ data: fixtures[table] || null, error: null })
  );
}

beforeEach(() => {
  jest.clearAllMocks();
});

// ----------------------------------------------------------------------
// Group 1: routes that compare req.user.id directly against a :user_id
// (or :customer_id) route param, with no extra DB lookup needed first.
// ----------------------------------------------------------------------
describe('landlord-scoped list/summary routes reject another landlord\'s id', () => {
  test.each([
    ['GET', `/api/properties/${OWNER_ID}`],
    ['GET', `/api/tenants/landlord/${OWNER_ID}`],
    ['GET', `/api/expenses/landlord/${OWNER_ID}`],
    ['GET', `/api/reports/${OWNER_ID}`],
    ['GET', `/api/insights/${OWNER_ID}`],
    ['GET', `/api/dashboard/${OWNER_ID}`],
    ['GET', `/api/maintenance/landlord/${OWNER_ID}`],
    ['GET', `/api/vendors/${OWNER_ID}`],
    ['GET', `/api/lease-renewals/landlord/${OWNER_ID}`],
    ['GET', `/api/sms/inbox/${OWNER_ID}`],
    ['GET', `/api/billing/plan/${OWNER_ID}`],
  ])('%s %s -> 403 for a different logged-in landlord', async (method, path) => {
    mockAsAttacker();
    const res = await request(app)[method.toLowerCase()](path).set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });
});

// ----------------------------------------------------------------------
// Group 2: routes that look up a resource by its own id (property_id,
// tenant_id, expense_id, vendor_id, document_id, customer_id,
// request_id) and must then resolve who owns it before acting.
// ----------------------------------------------------------------------
describe('resource routes reject a landlord who does not own the resource', () => {
  beforeEach(() => {
    mockAsAttacker();
    mockVictimOwnedResources();
  });

  test('PUT /api/properties/:property_id', async () => {
    const res = await request(app)
      .put('/api/properties/property_1')
      .set('Authorization', 'Bearer faketoken')
      .send({ address: 'hacked', city: 'hacked' });
    expect(res.status).toBe(403);
  });

  test('DELETE /api/properties/:property_id', async () => {
    const res = await request(app).delete('/api/properties/property_1').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('POST /api/tenants (adding a tenant under someone else\'s property)', async () => {
    const res = await request(app)
      .post('/api/tenants')
      .set('Authorization', 'Bearer faketoken')
      .send({ property_id: 'property_1', name: 'New Tenant', phone: '+15145550002' });
    expect(res.status).toBe(403);
  });

  test('PUT /api/tenants/:tenant_id', async () => {
    const res = await request(app)
      .put('/api/tenants/tenant_1')
      .set('Authorization', 'Bearer faketoken')
      .send({ name: 'hacked' });
    expect(res.status).toBe(403);
  });

  test('DELETE /api/tenants/:tenant_id', async () => {
    const res = await request(app).delete('/api/tenants/tenant_1').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('GET /api/tenants/:property_id', async () => {
    const res = await request(app).get('/api/tenants/property_1').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('POST /api/payments/mark-paid', async () => {
    const res = await request(app)
      .post('/api/payments/mark-paid')
      .set('Authorization', 'Bearer faketoken')
      .send({ tenant_id: 'tenant_1', amount: 100 });
    expect(res.status).toBe(403);
  });

  test('DELETE /api/payments/:tenant_id/latest', async () => {
    const res = await request(app).delete('/api/payments/tenant_1/latest').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('GET /api/payments/:tenant_id', async () => {
    const res = await request(app).get('/api/payments/tenant_1').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('GET /api/payments/property/:property_id', async () => {
    const res = await request(app).get('/api/payments/property/property_1').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('POST /api/expenses', async () => {
    const res = await request(app)
      .post('/api/expenses')
      .set('Authorization', 'Bearer faketoken')
      .send({ property_id: 'property_1', amount: 100, expense_date: '2026-01-01' });
    expect(res.status).toBe(403);
  });

  test('PUT /api/expenses/:expense_id', async () => {
    const res = await request(app)
      .put('/api/expenses/expense_1')
      .set('Authorization', 'Bearer faketoken')
      .send({ amount: 999 });
    expect(res.status).toBe(403);
  });

  test('DELETE /api/expenses/:expense_id', async () => {
    const res = await request(app).delete('/api/expenses/expense_1').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('GET /api/expenses/property/:property_id', async () => {
    const res = await request(app).get('/api/expenses/property/property_1').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('POST /api/documents/upload', async () => {
    const res = await request(app)
      .post('/api/documents/upload')
      .set('Authorization', 'Bearer faketoken')
      .field('property_id', 'property_1')
      .attach('file', Buffer.from('test file contents'), 'lease.pdf');
    expect(res.status).toBe(403);
  });

  test('GET /api/documents/tenant/:tenant_id', async () => {
    const res = await request(app).get('/api/documents/tenant/tenant_1').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('GET /api/documents/property/:property_id', async () => {
    const res = await request(app).get('/api/documents/property/property_1').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('DELETE /api/documents/:document_id', async () => {
    const res = await request(app).delete('/api/documents/document_1').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('POST /api/tenants/:tenant_id/invite', async () => {
    const res = await request(app).post('/api/tenants/tenant_1/invite').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('PUT /api/maintenance/:request_id', async () => {
    const res = await request(app)
      .put('/api/maintenance/request_1')
      .set('Authorization', 'Bearer faketoken')
      .send({ status: 'resolved' });
    expect(res.status).toBe(403);
  });

  test('PUT /api/vendors/:vendor_id', async () => {
    const res = await request(app)
      .put('/api/vendors/vendor_1')
      .set('Authorization', 'Bearer faketoken')
      .send({ name: 'hacked', phone: '+15145550003' });
    expect(res.status).toBe(403);
  });

  test('DELETE /api/vendors/:vendor_id', async () => {
    const res = await request(app).delete('/api/vendors/vendor_1').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('POST /api/tenants/:tenant_id/renewal-notice-sent', async () => {
    const res = await request(app).post('/api/tenants/tenant_1/renewal-notice-sent').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('DELETE /api/tenants/:tenant_id/renewal-notice-sent', async () => {
    const res = await request(app).delete('/api/tenants/tenant_1/renewal-notice-sent').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('POST /api/sms/send', async () => {
    const res = await request(app)
      .post('/api/sms/send')
      .set('Authorization', 'Bearer faketoken')
      .send({ tenant_id: 'tenant_1', message: 'hi' });
    expect(res.status).toBe(403);
  });

  test('GET /api/billing/invoices/:customer_id', async () => {
    const res = await request(app).get('/api/billing/invoices/customer_1').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });
});

// ----------------------------------------------------------------------
// Group 3: the tenant portal. These routes never take a client-supplied
// tenant id at all -- they derive "which tenant is this" from the
// session's own linked tenants row (auth_user_id = the logged-in user).
// The only way in is requireTenantAuth, so the regression to guard
// against is that check being skipped or bypassed, not an id parameter.
// ----------------------------------------------------------------------
describe('tenant portal routes reject a login with no linked tenant account', () => {
  beforeEach(() => {
    mockAsUserWithNoTenantAccount();
    // requireTenantAuth looks up `tenants` by auth_user_id; this login has
    // no matching row.
    supabaseMock.from.mockImplementation((table) => {
      if (table === 'tenants') return makeQueryResult({ data: null, error: { message: 'not found' } });
      return makeQueryResult({ data: null, error: null });
    });
  });

  test('GET /api/tenant-portal/me', async () => {
    const res = await request(app).get('/api/tenant-portal/me').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('PUT /api/tenant-portal/language', async () => {
    const res = await request(app)
      .put('/api/tenant-portal/language')
      .set('Authorization', 'Bearer faketoken')
      .send({ preferred_language: 'fr' });
    expect(res.status).toBe(403);
  });

  test('GET /api/tenant-portal/payments', async () => {
    const res = await request(app).get('/api/tenant-portal/payments').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('GET /api/tenant-portal/maintenance', async () => {
    const res = await request(app).get('/api/tenant-portal/maintenance').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });

  test('POST /api/tenant-portal/maintenance', async () => {
    const res = await request(app)
      .post('/api/tenant-portal/maintenance')
      .set('Authorization', 'Bearer faketoken')
      .field('title', 'Leaky faucet');
    expect(res.status).toBe(403);
  });
});

describe('tenant portal data routes are scoped to the session\'s own tenant row, never a client-supplied id', () => {
  test('GET /api/tenant-portal/payments only ever queries payments for the session\'s own tenant id', async () => {
    const myTenantRow = { id: 'my_tenant_id', property_id: 'property_1', rent_amount: 150000, auth_user_id: 'me_user' };
    supabaseMock.auth.getUser.mockResolvedValue({
      data: { user: { id: 'me_user', email: 'tenant@example.com' } },
      error: null,
    });
    supabaseMock.from.mockImplementation((table) => {
      if (table === 'tenants') return makeQueryResult({ data: myTenantRow, error: null });
      if (table === 'payments') return makeQueryResult({ data: [], error: null });
      return makeQueryResult({ data: null, error: null });
    });

    // Even though nothing in the request names a tenant id, confirm the
    // handler filters payments by the session's own tenant id and nothing
    // else -- this is the whole reason an attacker can't ask for someone
    // else's payment history through this route.
    const res = await request(app).get('/api/tenant-portal/payments').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(200);

    const paymentsBuilder = supabaseMock.from.mock.results.find(
      (r, i) => supabaseMock.from.mock.calls[i][0] === 'payments'
    ).value;
    expect(paymentsBuilder.eq).toHaveBeenCalledWith('tenant_id', 'my_tenant_id');
  });
});

// ----------------------------------------------------------------------
// Group 4: admin routes -- a valid session is not enough, the email must
// be on the ADMIN_EMAILS allowlist.
// ----------------------------------------------------------------------
describe('admin routes reject a logged-in user who is not on the admin allowlist', () => {
  test('GET /api/admin/stats', async () => {
    supabaseMock.auth.getUser.mockResolvedValue({
      data: { user: { id: ATTACKER_ID, email: 'not-admin@example.com' } },
      error: null,
    });
    const res = await request(app).get('/api/admin/stats').set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(403);
  });
});

// ----------------------------------------------------------------------
// Group 5: sanity check the other direction too -- the actual owner (and
// an admin) should NOT be rejected by these same checks. Without this, a
// route that rejected *everyone* (including its rightful owner) would
// still pass every test above.
// ----------------------------------------------------------------------
describe('the actual owner is not blocked by their own ownership check', () => {
  test('GET /api/properties/:user_id succeeds for the resource\'s own landlord', async () => {
    supabaseMock.auth.getUser.mockResolvedValue({
      data: { user: { id: OWNER_ID, email: 'owner@example.com' } },
      error: null,
    });
    supabaseMock.from.mockImplementation(() => makeQueryResult({ data: [], error: null }));

    const res = await request(app).get(`/api/properties/${OWNER_ID}`).set('Authorization', 'Bearer faketoken');
    expect(res.status).toBe(200);
  });

  test('PUT /api/properties/:property_id succeeds for the property\'s own landlord', async () => {
    supabaseMock.auth.getUser.mockResolvedValue({
      data: { user: { id: OWNER_ID, email: 'owner@example.com' } },
      error: null,
    });
    mockVictimOwnedResources();

    const res = await request(app)
      .put('/api/properties/property_1')
      .set('Authorization', 'Bearer faketoken')
      .send({ address: '1 Victim St', city: 'Montreal' });
    expect(res.status).not.toBe(403);
  });

  test('admin email is not blocked by GET /api/admin/stats', async () => {
    supabaseMock.auth.getUser.mockResolvedValue({
      data: { user: { id: 'admin_user', email: 'admin@example.com' } },
      error: null,
    });
    supabaseMock.auth.admin.listUsers.mockResolvedValue({ data: { users: [] }, error: null });
    supabaseMock.from.mockImplementation(() => makeQueryResult({ data: [], error: null }));

    const res = await request(app).get('/api/admin/stats').set('Authorization', 'Bearer faketoken');
    expect(res.status).not.toBe(403);
  });
});
