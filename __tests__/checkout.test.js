process.env.STRIPE_PRICE_STARTER = 'price_test_starter';
process.env.STRIPE_PRICE_GROWTH = 'price_test_growth';
process.env.STRIPE_PRICE_PORTFOLIO = 'price_test_portfolio';
process.env.FRONTEND_URL = 'https://app.test';
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

const stripeMock = Stripe();
const supabaseMock = createClient();

describe('POST /api/create-checkout-session', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('rejects a request with no auth token', async () => {
    const res = await request(app)
      .post('/api/create-checkout-session')
      .send({ tier: 'starter' });

    expect(res.status).toBe(401);
    expect(stripeMock.checkout.sessions.create).not.toHaveBeenCalled();
  });

  test('rejects a missing or unrecognized tier', async () => {
    supabaseMock.auth.getUser.mockResolvedValue({
      data: { user: { id: 'user_123', email: 'landlord@example.com' } },
      error: null,
    });

    const res = await request(app)
      .post('/api/create-checkout-session')
      .set('Authorization', 'Bearer faketoken')
      .send({ tier: 'enterprise' });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/tier is required/);
    expect(stripeMock.checkout.sessions.create).not.toHaveBeenCalled();
  });

  test('rejects a valid tier whose price is not configured on the server', async () => {
    supabaseMock.auth.getUser.mockResolvedValue({
      data: { user: { id: 'user_123', email: 'landlord@example.com' } },
      error: null,
    });
    delete process.env.STRIPE_PRICE_GROWTH;

    const res = await request(app)
      .post('/api/create-checkout-session')
      .set('Authorization', 'Bearer faketoken')
      .send({ tier: 'growth' });

    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/STRIPE_PRICE_GROWTH/);

    process.env.STRIPE_PRICE_GROWTH = 'price_test_growth'; // restore for later tests
  });

  test('creates a real Stripe checkout session for a valid, authenticated request', async () => {
    supabaseMock.auth.getUser.mockResolvedValue({
      data: { user: { id: 'user_123', email: 'landlord@example.com' } },
      error: null,
    });
    stripeMock.checkout.sessions.create.mockResolvedValue({
      id: 'cs_test_123',
      url: 'https://checkout.stripe.com/test_session',
    });

    const res = await request(app)
      .post('/api/create-checkout-session')
      .set('Authorization', 'Bearer faketoken')
      .send({ tier: 'starter' });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      success: true,
      url: 'https://checkout.stripe.com/test_session',
      sessionId: 'cs_test_123',
    });

    expect(stripeMock.checkout.sessions.create).toHaveBeenCalledWith(
      expect.objectContaining({
        mode: 'subscription',
        customer_email: 'landlord@example.com',
        line_items: [expect.objectContaining({ price: 'price_test_starter', quantity: 1 })],
        metadata: expect.objectContaining({ user_id: 'user_123', plan_tier: 'starter' }),
      })
    );
  });

  test('returns a 500 and does not crash if Stripe itself errors', async () => {
    supabaseMock.auth.getUser.mockResolvedValue({
      data: { user: { id: 'user_123', email: 'landlord@example.com' } },
      error: null,
    });
    stripeMock.checkout.sessions.create.mockRejectedValue(new Error('Stripe is down'));

    const res = await request(app)
      .post('/api/create-checkout-session')
      .set('Authorization', 'Bearer faketoken')
      .send({ tier: 'starter' });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Stripe is down');
  });
});