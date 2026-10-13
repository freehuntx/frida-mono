import { spawnSync } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { loadAgent, type LoadedAgent } from './support/agent'

interface DumpAgent {
  dump(format: 'dts' | 'cs' | 'json', assemblies?: string[]): Promise<string | { assemblies: string[]; types: { key: string }[] }>
}

describe('dump', () => {
  let agent: LoadedAgent<DumpAgent>

  beforeAll(async () => {
    agent = await loadAgent<DumpAgent>('test/e2e/agents/dump.ts')
  })

  afterAll(async () => {
    await agent?.unload()
  })

  it('produces the model of an assembly', async () => {
    const model = (await agent.exports.dump('json')) as { assemblies: string[]; types: { key: string }[] }
    expect(model.assemblies).toEqual(['TestLib'])
    expect(model.types.map((t) => t.key)).toEqual(expect.arrayContaining(['FridaMono.Tests.Dog', 'FridaMono.Tests.Dog+Collar', 'FridaMono.Tests.Box`1', 'FridaMono.Tests.Color']))
  })

  it('produces a C#-like listing', async () => {
    const cs = (await agent.exports.dump('cs')) as string
    expect(cs).toContain('public sealed class Dog : FridaMono.Tests.Animal, FridaMono.Tests.IGreeter')
    expect(cs).toContain('public static bool TryDouble(int x, out int result);')
  })

  it('generates typings that a typed example compiles against', async () => {
    const dts = (await agent.exports.dump('dts')) as string
    mkdirSync('.cache/typed', { recursive: true })
    writeFileSync('.cache/typed/TestLib.d.ts', dts)
    const tsc = spawnSync('npx', ['tsc', '-p', 'test/e2e/typed/tsconfig.json'], { encoding: 'utf8' })
    expect(`${tsc.stdout}${tsc.stderr}`).toBe('')
    expect(tsc.status).toBe(0)
  }, 120_000)

  it('generates typings for a whole framework assembly that compile', async () => {
    const dts = (await agent.exports.dump('dts', ['mscorlib'])) as string
    mkdirSync('.cache/typed-corlib', { recursive: true })
    writeFileSync('.cache/typed-corlib/mscorlib.d.ts', dts)
    writeFileSync(
      '.cache/typed-corlib/tsconfig.json',
      JSON.stringify({
        extends: '../../tsconfig.json',
        compilerOptions: { noEmit: true, skipLibCheck: false, paths: { 'frida-mono': ['../../src/index.ts'] } },
        include: ['mscorlib.d.ts', '../../types']
      })
    )
    const tsc = spawnSync('npx', ['tsc', '-p', '.cache/typed-corlib/tsconfig.json'], { encoding: 'utf8', maxBuffer: 1 << 26 })
    const errors = `${tsc.stdout}${tsc.stderr}`.split('\n').filter((l) => l.includes('error TS'))
    console.log(`mscorlib.d.ts: ${dts.length} chars, ${errors.length} errors\n${errors.slice(0, 30).join('\n')}`)
    expect(errors).toEqual([])
  }, 300_000)
})
