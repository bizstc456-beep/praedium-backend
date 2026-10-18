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

const Stripe = require('stripe');
const { createClient } = require('@supabase/supabase-js');
const twilio = require('twilio');

const stripeMock = Stripe();
const supabaseMock = createClient();
const twilioMock = twilio();

function makeQueryResult(result) {
  const builder = {};
  ['select', 'update', 'insert', 'delete', 'eq', 'order', 'limit'].forEach((method) => {
    builder[method] = jest.fn(() => builder);
  });
  builder.single = jest.fn(() => Promise.resolve(result));
  builder.then = (onFulfilled, onRejected) => Promise.resolve(result).then(onFulfilled, onRejected);
  return builder;
}

function sendWebhookEvent(event) {
  stripeMock.webhooks.constructEvent.mockReturnValue(event);
  return request(app)
    .post('/api/webhooks/stripe')
    .set('Stripe-Signature', 'irrelevant-because-constructEvent-is-mocked')
    .send(event);
}

describe('POST /api/webhooks/stripe', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('rejects an event with an invalid signature', async () => {
    stripeMock.webhooks.constructEvent.mockImplementation(() => {
      throw new Error('No signatures found matching the expected signature for payload');
    });

    const res = await request(app)
      .post('/api/webhooks/stripe')
      .set('Stripe-Signature', 'bad-signature')
      .send({ type: 'invoice.payment_failed' });

    expect(res.status).toBe(400);
  });

  test('checkout.session.completed activates the right customer row by user_id', async () => {
    supabaseMock.from.mockReturnValue(makeQueryResult({ data: null, error: null }));

    const res = await sendWebhookEvent({
      id: 'evt_1',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_test_123',
          mode: 'subscription',
          customer: 'cus_abc',
          subscription: 'sub_abc',
          metadata: { user_id: 'user_123', plan_tier: 'growth' },
        },
      },
    });

    expect(res.status).toBe(200);
    expect(supabaseMock.from).toHaveBeenCalledWith('customers');
    const builder = supabaseMock.from.mock.results[0].value;
    expect(builder.update).toHaveBeenCalledWith(
      expect.objectContaining({
        stripe_customer_id: 'cus_abc',
        stripe_subscription_id: 'sub_abc',
        subscription_status: 'trialing',
        plan_tier: 'growth',
      })
    );
    expect(builder.eq).toHaveBeenCalledWith('user_id', 'user_123');
  });

  test('invoice.payment_succeeded marks the customer active', async () => {
    supabaseMock.from.mockReturnValue(makeQueryResult({ data: null, error: null }));

    const res = await sendWebhookEvent({
      id: 'evt_2',
      type: 'invoice.payment_succeeded',
      data: { object: { id: 'in_1', customer: 'cus_abc' } },
    });

    expect(res.status).toBe(200);
    const builder = supabaseMock.from.mock.results[0].value;
    expect(builder.update).toHaveBeenCalledWith({ subscription_status: 'active' });
    expect(builder.eq).toHaveBeenCalledWith('stripe_customer_id', 'cus_abc');
  });

  describe('invoice.payment_failed', () => {
    function mockCustomersBuilder(result) {
      supabaseMock.from.mockImplementation((table) => {
        if (table === 'customers') return makeQueryResult(result);
        return makeQueryResult({ data: null, error: null });
      });
    }

    test('marks the customer past_due and texts the owner', async () => {
      mockCustomersBuilder({
        data: { user_id: 'user_123', email: 'landlord@example.com' },
        error: null,
      });
      twilioMock.messages.create.mockResolvedValue({ sid: 'SM123', status: 'queued' });

      const res = await sendWebhookEvent({
        id: 'evt_3',
        type: 'invoice.payment_failed',
        data: {
          object: {
            id: 'in_2',
            customer: 'cus_abc',
            customer_email: 'landlord@example.com',
            amount_due: 4999,
          },
        },
      });

      expect(res.status).toBe(200);
      expect(supabaseMock.from).toHaveBeenCalledWith('customers');

      expect(twilioMock.messages.create).toHaveBeenCalledTimes(1);
      const smsArgs = twilioMock.messages.create.mock.calls[0][0];
      expect(smsArgs.to).toBe('+15145551234');
      expect(smsArgs.body).toMatch(/landlord@example\.com/);
      expect(smsArgs.body).toMatch(/\$49\.99/);
      expect(smsArgs.body).toMatch(/past_due/);
    });

    test('still returns 200 to Stripe if the SMS itself fails', async () => {
      mockCustomersBuilder({
        data: { user_id: 'user_123', email: 'landlord@example.com' },
        error: null,
      });
      twilioMock.messages.create.mockRejectedValue(new Error('Twilio is down'));

      const res = await sendWebhookEvent({
        id: 'evt_4',
        type: 'invoice.payment_failed',
        data: { object: { id: 'in_3', customer: 'cus_abc', amount_due: 2500 } },
      });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ received: true });
    });

    test('skips the SMS entirely when OWNER_PHONE_NUMBER is not configured', async () => {
      const originalNumber = process.env.OWNER_PHONE_NUMBER;
      delete process.env.OWNER_PHONE_NUMBER;

      mockCustomersBuilder({
        data: { user_id: 'user_123', email: 'landlord@example.com' },
        error: null,
      });

      const res = await sendWebhookEvent({
        id: 'evt_5',
        type: 'invoice.payment_failed',
        data: { object: { id: 'in_4', customer: 'cus_abc', amount_due: 1000 } },
      });

      expect(res.status).toBe(200);
      expect(twilioMock.messages.create).not.toHaveBeenCalled();

      process.env.OWNER_PHONE_NUMBER = originalNumber;
    });
  });
});