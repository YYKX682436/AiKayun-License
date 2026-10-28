export type BillingPlan = 'monthly' | 'yearly';

function daysInUtcMonth(year: number, monthIndex: number): number {
  return new Date(Date.UTC(year, monthIndex + 1, 0)).getUTCDate();
}

export function addCalendarPeriod(start: Date, plan: BillingPlan, anchorDay: number): Date {
  if (!Number.isInteger(anchorDay) || anchorDay < 1 || anchorDay > 31) throw new RangeError('Invalid billing anchor day');
  const year = start.getUTCFullYear() + (plan === 'yearly' ? 1 : 0);
  const month = start.getUTCMonth() + (plan === 'monthly' ? 1 : 0);
  const normalizedYear = year + Math.floor(month / 12);
  const normalizedMonth = ((month % 12) + 12) % 12;
  const day = Math.min(anchorDay, daysInUtcMonth(normalizedYear, normalizedMonth));
  return new Date(Date.UTC(
    normalizedYear,
    normalizedMonth,
    day,
    start.getUTCHours(),
    start.getUTCMinutes(),
    start.getUTCSeconds(),
    start.getUTCMilliseconds(),
  ));
}

export function renewalPeriod(
  plan: BillingPlan,
  confirmedEnd: Date,
  anchorDay: number,
  now: Date,
): { start: Date; end: Date; anchorDay: number; anchor: Date } {
  if (confirmedEnd.getTime() > now.getTime()) {
    const start = new Date(confirmedEnd);
    return { start, end: addCalendarPeriod(start, plan, anchorDay), anchorDay, anchor: new Date(start) };
  }
  const start = new Date(now);
  const newAnchorDay = start.getUTCDate();
  return { start, end: addCalendarPeriod(start, plan, newAnchorDay), anchorDay: newAnchorDay, anchor: new Date(start) };
}
