import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/unit/**/*.test.ts', 'test/interop/**/*.test.ts'],
    testTimeout: 15000,
    hookTimeout: 15000,
    pool: 'forks',
    maxWorkers: 2,
  },
});
