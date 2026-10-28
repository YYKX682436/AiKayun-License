import { describe, expect, it } from 'vitest';
import { addCalendarPeriod, renewalPeriod } from '../../src/entitlements/calendar.js';

describe('UTC calendar billing periods', () => {
  it('preserves a month-end anchor through short and long months', () => {
    const january = new Date('2024-01-31T16:23:45.678Z');
    const february = addCalendarPeriod(january, 'monthly', 31);
    expect(february.toISOString()).toBe('2024-02-29T16:23:45.678Z');
    expect(addCalendarPeriod(february, 'monthly', 31).toISOString()).toBe('2024-03-31T16:23:45.678Z');
  });

  it('handles leap-year annual renewal and keeps the original anchor day', () => {
    expect(addCalendarPeriod(new Date('2024-02-29T08:00:00.000Z'), 'yearly', 29).toISOString())
      .toBe('2025-02-28T08:00:00.000Z');
    expect(addCalendarPeriod(new Date('2025-02-28T08:00:00.000Z'), 'yearly', 29).toISOString())
      .toBe('2026-02-28T08:00:00.000Z');
  });

  it('extends from the confirmed end when active and resets the anchor after expiry', () => {
    const active = renewalPeriod('monthly', new Date('2026-01-31T00:00:00.000Z'), 31, new Date('2026-01-01T00:00:00.000Z'));
    expect(active.start.toISOString()).toBe('2026-01-31T00:00:00.000Z');
    expect(active.end.toISOString()).toBe('2026-02-28T00:00:00.000Z');
    expect(active.anchorDay).toBe(31);
    const expired = renewalPeriod('monthly', new Date('2025-12-01T00:00:00.000Z'), 31, new Date('2026-01-30T12:00:00.000Z'));
    expect(expired.start.toISOString()).toBe('2026-01-30T12:00:00.000Z');
    expect(expired.end.toISOString()).toBe('2026-02-28T12:00:00.000Z');
    expect(expired.anchorDay).toBe(30);
  });
});
