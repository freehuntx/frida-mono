import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { loadAgent, type LoadedAgent } from './support/agent'
import { currentRuntime } from './support/runtime'

interface SmokeAgent {
  info(): Promise<{ module: string; buildInfo: string | null; exportCount: number }>
}

describe('smoke', () => {
  const runtime = currentRuntime()
  let agent: LoadedAgent<SmokeAgent>

  beforeAll(async () => {
    agent = await loadAgent<SmokeAgent>('test/e2e/agents/smoke.ts')
  })

  afterAll(async () => {
    await agent?.unload()
  })

  it(`finds the ${runtime.name} runtime`, async () => {
    const info = await agent.exports.info()
    console.log(`${runtime.name}: ${info.buildInfo} (in ${info.module}, ${info.exportCount} exports)`)
    if (runtime.version === null) expect(info.buildInfo).toBeNull()
    else expect(info.buildInfo?.startsWith(runtime.version)).toBe(true)
    expect(info.exportCount).toBeGreaterThan(500)
  })
})
