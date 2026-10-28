export class LicenseApiError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
    message = code,
  ) {
    super(message);
    this.name = 'LicenseApiError';
  }
}

export function invariant(condition: unknown, statusCode: number, code: string): asserts condition {
  if (!condition) throw new LicenseApiError(statusCode, code);
}
