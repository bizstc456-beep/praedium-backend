const {
  PLAN_TIERS,
  DEFAULT_PLAN_TIER,
  inferUnitCount,
  isValidTierKey,
  resolveTierKey,
  wouldExceedCap,
} = require('../lib/planLogic');

describe('inferUnitCount', () => {
  test('duplex/triplex/fourplex map to their known unit counts', () => {
    expect(inferUnitCount('duplex')).toBe(2);
    expect(inferUnitCount('triplex')).toBe(3);
    expect(inferUnitCount('fourplex')).toBe(4);
  });

  test('single-family, condo, unset, and unknown types all count as one unit', () => {
    expect(inferUnitCount('single-family')).toBe(1);
    expect(inferUnitCount('condo')).toBe(1);
    expect(inferUnitCount(undefined)).toBe(1);
    expect(inferUnitCount('something-new')).toBe(1);
  });
});

describe('isValidTierKey', () => {
  test('accepts every real tier key', () => {
    Object.keys(PLAN_TIERS).forEach((key) => {
      expect(isValidTierKey(key)).toBe(true);
    });
  });

  test('rejects anything else, including a tier guessed from request body', () => {
    expect(isValidTierKey('enterprise')).toBe(false);
    expect(isValidTierKey('')).toBe(false);
    expect(isValidTierKey(undefined)).toBe(false);
  });
});

describe('resolveTierKey', () => {
  test('passes through a recognized tier', () => {
    expect(resolveTierKey('growth')).toBe('growth');
  });

  test('falls back to the default tier for a missing or unrecognized value', () => {
    expect(resolveTierKey(undefined)).toBe(DEFAULT_PLAN_TIER);
    expect(resolveTierKey('deprecated-tier')).toBe(DEFAULT_PLAN_TIER);
  });
});

describe('wouldExceedCap -- the actual billing enforcement boundary', () => {
  test('starter (max 5) allows exactly up to its cap, blocks past it', () => {
    expect(wouldExceedCap('starter', 4, 1)).toBe(false); // lands exactly at 5
    expect(wouldExceedCap('starter', 5, 1)).toBe(true);  // would land at 6
  });

  test('growth (max 20) enforces its own, higher cap', () => {
    expect(wouldExceedCap('growth', 19, 1)).toBe(false);
    expect(wouldExceedCap('growth', 20, 1)).toBe(true);
  });

  test('portfolio (unlimited) never exceeds, even at a large count', () => {
    expect(wouldExceedCap('portfolio', 999, 50)).toBe(false);
  });

  test('an unrecognized tier is treated as starter for safety', () => {
    expect(wouldExceedCap('nonexistent-tier', 5, 1)).toBe(true);
  });
});
