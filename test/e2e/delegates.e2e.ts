import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { loadAgent, type LoadedAgent } from './support/agent'

describe('delegates', () => {
  let agent: LoadedAgent<{ run(): Promise<Record<string, unknown>> }>
  let r: Record<string, unknown>

  beforeAll(async () => {
    agent = await loadAgent('test/e2e/agents/delegates.ts')
    r = await agent.exports.run()
  })

  afterAll(async () => {
    await agent?.unload()
  })

  it('turns JS functions into Func/Action delegates', () => {
    expect(r.func).toBe(15)
    expect(r.twoArgs).toBe('ab!')
    expect(r.action).toBe(2)
  })

  it('boxes and unboxes structs and passes objects as bridge instances', () => {
    expect(r.struct).toEqual({ X: 10, Y: 2 })
    expect(r.customDelegate).toBe(103)
  })

  it('creates delegates explicitly with Mono.delegate', () => {
    expect(r.explicit).toEqual([1, 'System.Action'])
  })

  it('subscribes JS functions to events and removes them again', () => {
    expect(r.event).toEqual(['Rex:EventArgs'])
  })

  it('returns the default value when the function throws, and rejects functions for non-delegates', () => {
    expect(r.throws).toBe(0)
    expect(r.notADelegate).toMatchObject({ threw: 'OverloadError' })
  })
})
