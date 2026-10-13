import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit',
          include: ['test/unit/**/*.test.ts'],
          environment: 'node'
        }
      },
      {
        test: {
          name: 'e2e',
          include: ['test/e2e/**/*.e2e.ts'],
          environment: 'node',
          testTimeout: 60_000,
          hookTimeout: 120_000,
          // One target process per runtime; tests share it, so never run files in parallel.
          fileParallelism: false,
          // Files share one Frida session (see test/e2e/support/agent.ts), so they must share module state.
          isolate: false,
          maxWorkers: 1
        }
      }
    ]
  }
})
