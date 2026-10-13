import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { loadAgent, type LoadedAgent } from './support/agent'
import { currentRuntime } from './support/runtime'

interface AgentError {
  name: string
  message: string
  missing: boolean
}

interface RuntimeAgent {
  info(): Promise<{ ready: boolean; version: string | null; module: string; capabilities: Record<string, boolean> }>
  perform(): Promise<{ before: boolean; after: boolean; corlib: string }>
  classOfString(): Promise<string>
  assemblies(): Promise<string[]>
  missing(): Promise<{ absent: string; call: AgentError | null; bind: AgentError | null }>
  waitForLazy(): Promise<unknown>
  loadLazy(): Promise<{ name: string; jsThread: number }>
  lazyResult(): Promise<{ thread: number; assembly: string } | null>
  installLoadListener(): Promise<void>
  loadLazyB(): Promise<string>
}

describe('runtime', () => {
  const runtime = currentRuntime()
  let agent: LoadedAgent<RuntimeAgent>

  beforeAll(async () => {
    agent = await loadAgent<RuntimeAgent>('test/e2e/agents/runtime.ts')
  })

  afterAll(async () => {
    await agent?.unload()
  })

  it('reports the runtime', async () => {
    const info = await agent.exports.info()
    expect(info.ready).toBe(true)
    if (runtime.version === null) expect(info.version).toBeNull()
    else expect(info.version?.startsWith(runtime.version)).toBe(true)
    expect(info.capabilities.buildInfo).toBe(runtime.version !== null)
  })

  it('perform attaches the JS thread and calls the typed API', async () => {
    const result = await agent.exports.perform()
    expect(result.before).toBe(false)
    expect(result.after).toBe(true)
    expect(result.corlib).toBe('mscorlib')
    expect(await agent.exports.classOfString()).toBe('System.String')
  })

  it('lists loaded assemblies', async () => {
    const names = await agent.exports.assemblies()
    expect(names).toContain('mscorlib')
    expect(names).toContain('TestLib')
    expect(names).not.toContain('LazyA')
  })

  it('throws a clear error for functions the runtime lacks', async () => {
    const result = await agent.exports.missing()
    expect(result.call?.missing).toBe(true)
    expect(result.call?.message).toContain(`${result.absent} is not exported`)
    expect(result.bind?.name).toBe('MonoApiMissingError')
  })

  it('perform waits for an assembly and runs on the loading thread', async () => {
    expect(await agent.exports.waitForLazy()).toBeNull()
    const loaded = await agent.exports.loadLazy()
    expect(loaded.name).toBe('LazyA')
    const result = await agent.exports.lazyResult()
    expect(result?.assembly).toBe('LazyA')
    expect(result?.thread).toBe(loaded.jsThread)
  })

  it('survives assembly loads after an agent with a load hook unloaded', async () => {
    const first = await loadAgent<RuntimeAgent>('test/e2e/agents/runtime.ts')
    await first.exports.installLoadListener()
    await first.unload()
    // The first agent's load hook is now a no-op stub; loading must not crash the process.
    expect(await agent.exports.loadLazyB()).toBe('LazyB')
    expect(await agent.exports.classOfString()).toBe('System.String')
  })
})
