import { afterEach, describe, expect, it, vi } from 'vitest';
import { runAdminCli } from '../../src/admin/cli.js';
import { openAdminSession } from '../../src/admin/policy.js';
import { createLicenseRequestDigest, issueActivationCodeRequestDigest } from '../../src/admin/service.js';

function fakeStream(isTTY = false) {
  let contents = '';
  return {
    stream: {
      isTTY,
      write(chunk: string | Uint8Array) {
        contents += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
        return true;
      },
    } as unknown as NodeJS.WriteStream,
    text: () => contents,
  };
}

describe('local admin CLI boundary', () => {
  const originalNodeEnv = process.env['NODE_ENV'];

  afterEach(() => {
    if (originalNodeEnv === undefined) delete process.env['NODE_ENV'];
    else process.env['NODE_ENV'] = originalNodeEnv;
    vi.restoreAllMocks();
  });

  it('rejects an actor flag instead of treating command text as identity', async () => {
    const stdout = fakeStream();
    const stderr = fakeStream();
    const status = await runAdminCli([
      'license', 'revoke', '--operation-id', '00000000-0000-4000-8000-000000000001',
      '--license-id', '00000000-0000-4000-8000-000000000002', '--expected-revision', '1',
      '--reason', 'manual reason', '--actor', 'forged-admin',
    ], stdout.stream, stderr.stream);
    expect(status).toBe(2);
    expect(stderr.text()).toContain('ADMIN_ARGUMENT_UNKNOWN');
  });

  it('requires an interactive terminal before issuing an activation-code secret', async () => {
    const request = {
      operationId: '00000000-0000-4000-8000-000000000001',
      licenseId: '00000000-0000-4000-8000-000000000002',
      expectedRevision: '1',
      reason: 'manual activation code issue',
    };
    const digest = issueActivationCodeRequestDigest(request);
    const stdout = fakeStream(false);
    const stderr = fakeStream();
    const status = await runAdminCli([
      'license', 'issue-code', '--operation-id', request.operationId,
      '--license-id', request.licenseId, '--expected-revision', request.expectedRevision,
      '--reason', request.reason, '--confirm-digest', digest,
    ], stdout.stream, stderr.stream);
    expect(status).toBe(2);
    expect(stderr.text()).toContain('ADMIN_ACTIVATION_CODE_REQUIRES_TTY');
    expect(stdout.text()).toBe('');
  });

  it('requires protected confirmation over the exact create request', () => {
    const request = {
      operationId: '00000000-0000-4000-8000-000000000001',
      licenseId: '00000000-0000-4000-8000-000000000002',
      expectedRevision: '0' as const,
      plan: 'monthly' as const,
      accountId: 'account-1',
      reason: 'manual confirmed authorization',
    };
    const original = createLicenseRequestDigest(request);
    const changed = createLicenseRequestDigest({ ...request, reason: 'different confirmed reason' });
    expect(original).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(changed).not.toBe(original);
  });

  it('prints a review digest without opening a database or performing a write', async () => {
    const request = {
      operationId: '00000000-0000-4000-8000-000000000001',
      licenseId: '00000000-0000-4000-8000-000000000002',
      expectedRevision: '0',
      plan: 'yearly',
      accountId: 'account-1',
      reason: 'manual confirmed authorization',
    };
    const digest = createLicenseRequestDigest({ ...request, expectedRevision: '0', plan: 'yearly' });
    const stdout = fakeStream();
    const stderr = fakeStream();
    const status = await runAdminCli([
      'license', 'create', '--operation-id', request.operationId, '--license-id', request.licenseId,
      '--expected-revision', request.expectedRevision, '--plan', request.plan,
      '--account-id', request.accountId, '--reason', request.reason,
    ], stdout.stream, stderr.stream);
    expect(status).toBe(0);
    expect(stderr.text()).toBe('');
    expect(JSON.parse(stdout.text())['request_digest']).toBe(digest);
    expect(JSON.parse(stdout.text())['review_required']).toBe(true);
  });

  it('refuses to open the admin service in production mode', async () => {
    process.env['NODE_ENV'] = 'production';
    await expect(openAdminSession('/does/not/need/to/exist'))
      .rejects.toMatchObject({ code: 'ADMIN_CLI_DISABLED_IN_PRODUCTION' });
  });
});
