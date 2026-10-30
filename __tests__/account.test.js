process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test_secret';
process.env.OWNER_PHONE_NUMBER = '+15145551234';
process.env.SENTRY_DSN = '';

jest.mock('stripe', () => {
  const mockStripeClient = {
    checkout: { sessions: { create: jest.fn() } },
    webhooks: { constructEvent: jest.fn() },
  };
  return jest.fn(() => mockStripeClient);
});

jest.mock('@supabase/supabase-js', () => {
  const mockSupabaseClient = {
    auth: { getUser: jest.fn() },
    from: jest.fn(),
  };
  return { createClient: jest.fn(() => mockSupabaseClient) };
});

jest.mock('twilio', () => {
  const mockTwilioClient = { messages: { create: jest.fn() } };
  return jest.fn(() => mockTwilioClient);
});

const request = require('supertest');
const app = require('../server');

const { createClient } = require('@supabase/supabase-js');
const twilio = require('twilio');

const supabaseMock = createClient();
const twilioMock = twilio();

// Every chain method returns the same builder, which also implements
// .then() so `await` resolves correctly regardless of where in the
// chain it's invoked -- same pattern as webhook.test.js. One builder
// instance gets reused across multiple .from() calls in the delete
// -request tests below (select-then-update), which is fine since we
// only ever read .single()'s resolved value or the chain's own
// .then()-resolved { error }.
function makeQueryResult(result) {
  const builder = {};
  ['select', 'update', 'insert', 'delete', 'eq', 'order', 'limit'].forEach((method) => {
    builder[method] = jest.fn(() => builder);
  });
  builder.single = jest.fn(() => Promise.resolve(result));
  builder.then = (onFulfilled, onRejected) => Promise.resolve(result).then(onFulfilled, onRejected);
  return builder;
}

function mockAuthenticatedUser(user = { id: 'user_123', email: 'landlord@example.com' }) {
  supabaseMock.auth.getUser.mockResolvedValue({ data: { user }, error: null });
}

describe('GET /api/account/export', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('rejects a request with no Authorization header', async () => {
    const res = await request(app).get('/api/account/export');
    expect(res.status).toBe(401);
  });

  test('returns 500 if the customer row fails to load', async () => {
    mockAuthenticatedUser();
    supabaseMock.from.mockImplementation((table) => {
      if (table === 'customers') {
        return makeQueryResult({
          data: null,
          error: { code: 'PGRST116', message: 'Cannot coerce the result to a single JSON object' },
        });
      }
      return makeQueryResult({ data: [], error: null });
    });

    const res = await request(app)
      .get('/api/account/export')
      .set('Authorization', 'Bearer faketoken');

    expect(res.status).toBe(500);
  });

  test('returns 500 if the sms_messages query fails', async () => {
    mockAuthenticatedUser();
    supabaseMock.from.mockImplementation((table) => {
      if (table === 'customers') {
        return makeQueryResult({
          data: { user_id: 'user_123', email: 'landlord@example.com', name: 'Felix' },
          error: null,
        });
      }
      if (table === 'sms_messages') {
        return makeQueryResult({ data: null, error: { message: 'boom' } });
      }
      return makeQueryResult({ data: [], error: null });
    });

    const res = await request(app)
      .get('/api/account/export')
      .set('Authorization', 'Bearer faketoken');

    expect(res.status).toBe(500);
  });

  test('returns the account snapshot and sms history as a downloadable JSON file', async () => {
    mockAuthenticatedUser();
    const accountRow = {
      user_id: 'user_123',
      email: 'landlord@example.com',
      name: 'Felix',
      phone: null,
      plan_tier: 'starter',
      subscription_status: 'active',
      deletion_requested_at: null,
    };
    const smsRows = [
      {
        id: 'sms_1',
        user_id: 'user_123',
        to_phone: '+15145551234',
        message: 'Hi',
        status: 'queued',
        created_at: '2026-10-11T09:00:02.591Z',
      },
    ];

    supabaseMock.from.mockImplementation((table) => {
      if (table === 'customers') return makeQueryResult({ data: accountRow, error: null });
      if (table === 'sms_messages') return makeQueryResult({ data: smsRows, error: null });
      return makeQueryResult({ data: [], error: null });
    });

    const res = await request(app)
      .get('/api/account/export')
      .set('Authorization', 'Bearer faketoken');

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.headers['content-disposition']).toMatch(/attachment/);
    expect(res.headers['content-disposition']).toMatch(/praedium-account-export-.*\.json/);

    expect(res.body.account).toEqual(accountRow);
    expect(res.body.sms_history).toEqual(smsRows);
    expect(res.body.export_generated_at).toEqual(expect.any(String));
  });
});

describe('POST /api/account/delete-request', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('rejects a request with no Authorization header', async () => {
    const res = await request(app).post('/api/account/delete-request');
    expect(res.status).toBe(401);
  });

  test('returns 500 if the customer row fails to load', async () => {
    mockAuthenticatedUser();
    supabaseMock.from.mockReturnValue(makeQueryResult({ data: null, error: { message: 'boom' } }));

    const res = await request(app)
      .post('/api/account/delete-request')
      .set('Authorization', 'Bearer faketoken');

    expect(res.status).toBe(500);
  });

  test('returns the existing timestamp without re-notifying when already requested', async () => {
    mockAuthenticatedUser();
    const existingTimestamp = '2026-10-18T22:20:19.935Z';
    supabaseMock.from.mockReturnValue(
      makeQueryResult({
        data: {
          user_id: 'user_123',
          email: 'landlord@example.com',
          name: 'Felix',
          deletion_requested_at: existingTimestamp,
        },
        error: null,
      })
    );

    const res = await request(app)
      .post('/api/account/delete-request')
      .set('Authorization', 'Bearer faketoken');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      success: true,
      already_requested: true,
      deletion_requested_at: existingTimestamp,
    });
    expect(twilioMock.messages.create).not.toHaveBeenCalled();
  });

  test('flags the account and texts the owner when not already requested', async () => {
    mockAuthenticatedUser();
    supabaseMock.from.mockReturnValue(
      makeQueryResult({
        data: {
          user_id: 'user_123',
          email: 'landlord@example.com',
          name: 'Felix',
          deletion_requested_at: null,
        },
        error: null,
      })
    );
    twilioMock.messages.create.mockResolvedValue({ sid: 'SM456', status: 'queued' });

    const res = await request(app)
      .post('/api/account/delete-request')
      .set('Authorization', 'Bearer faketoken');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.already_requested).toBe(false);
    expect(res.body.deletion_requested_at).toEqual(expect.any(String));

    const builder = supabaseMock.from.mock.results[0].value;
    expect(builder.update).toHaveBeenCalledWith({ deletion_requested_at: res.body.deletion_requested_at });
    expect(builder.eq).toHaveBeenCalledWith('user_id', 'user_123');

    expect(twilioMock.messages.create).toHaveBeenCalledTimes(1);
    const smsArgs = twilioMock.messages.create.mock.calls[0][0];
    expect(smsArgs.to).toBe('+15145551234');
    expect(smsArgs.body).toMatch(/landlord@example\.com/);
    expect(smsArgs.body).toMatch(/deletion/i);
  });

  test('still succeeds even if the SMS notification fails', async () => {
    mockAuthenticatedUser();
    supabaseMock.from.mockReturnValue(
      makeQueryResult({
        data: {
          user_id: 'user_123',
          email: 'landlord@example.com',
          name: 'Felix',
          deletion_requested_at: null,
        },
        error: null,
      })
    );
    twilioMock.messages.create.mockRejectedValue(new Error('Twilio is down'));

    const res = await request(app)
      .post('/api/account/delete-request')
      .set('Authorization', 'Bearer faketoken');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('skips the SMS entirely when OWNER_PHONE_NUMBER is not configured', async () => {
    const originalNumber = process.env.OWNER_PHONE_NUMBER;
    delete process.env.OWNER_PHONE_NUMBER;

    mockAuthenticatedUser();
    supabaseMock.from.mockReturnValue(
      makeQueryResult({
        data: {
          user_id: 'user_123',
          email: 'landlord@example.com',
          name: 'Felix',
          deletion_requested_at: null,
        },
        error: null,
      })
    );

    const res = await request(app)
      .post('/api/account/delete-request')
      .set('Authorization', 'Bearer faketoken');

    expect(res.status).toBe(200);
    expect(twilioMock.messages.create).not.toHaveBeenCalled();

    process.env.OWNER_PHONE_NUMBER = originalNumber;
  });
});