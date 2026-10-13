import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { loadAgent, type LoadedAgent } from './support/agent'

interface HooksAgent {
  run(): Promise<Record<string, unknown>>
  otherThread(): Promise<{ last: number; after: number }>
  installForUnload(): Promise<void>
  callTwice(x: number): Promise<number>
}

const NS = 'FridaMono.Tests'

describe('hooks', () => {
  let agent: LoadedAgent<HooksAgent>
  let r: Record<string, unknown>

  beforeAll(async () => {
    agent = await loadAgent<HooksAgent>('test/e2e/agents/hooks.ts')
    r = await agent.exports.run()
  })

  afterAll(async () => {
    await agent?.unload()
  })

  it('overrides static methods, called from managed code and from JS, with $original', () => {
    expect(r.staticInt).toEqual([10, 100, 100])
  })

  it('marshals primitives, strings and floats through hooks', () => {
    expect(r).toMatchObject({
      string: 'Hi Hello BOB',
      floats: [3.5, [1.5, 2]],
      long: '2199023255554n',
      bool: [false, true]
    })
  })

  it('scopes overrides to all instances (via prototype) or one instance', () => {
    expect(r.instanceAll).toEqual([1001, 1002])
    expect(r.instanceOne).toEqual([-11, 12])
  })

  it('passes structs per the managed ABI: integer chunks, hidden return buffers', () => {
    expect(r.smallStruct).toBe('103,8')
    expect(r.floatStruct).toEqual(['2.5,4,106', [{ X: 1, Y: 2, Z: 3 }, 2], { X: 2, Y: 4, Z: 6 }])
    expect(r.bigStruct).toEqual(['8,31,-1', [{ A: '3n', B: '30n', C: '300n' }, '1n']])
  })

  it('writes out/ref parameters back', () => {
    expect(r.outParam).toBe(4000)
  })

  it('keeps managed exceptions inside the hook and never crashes the caller', () => {
    expect(r.managedExceptionSwallowed).toEqual(['5', '0'])
    expect(r.managedExceptionCaughtInHook).toBe('777')
    expect(r.jsError).toBe(0)
  })

  it('supports $attach, $revert and $overload', () => {
    expect(r.attach).toEqual([
      1012,
      [
        ['enter', 5],
        ['leave', 12]
      ]
    ])
    expect(r.revert).toEqual([0, 10, 0])
    expect(r.overloadedNeedsChoice).toMatchObject({ threw: 'OverloadError' })
    expect(r.overloadChosen).toEqual(['hooked int', 'string'])
    expect(r.assignmentRejected).toMatchObject({ threw: 'TypeError' })
  })

  it('traces calls and symbolicates code addresses', () => {
    expect(r.trace).toEqual([`→ ${NS}.HookTargets.CallTwice(21)`, `← ${NS}.HookTargets.CallTwice = 42`])
    expect(r.symbolicate).toEqual([`${NS}.HookTargets:Twice (int) + 0x1`, null])
  })

  it('hooks calls made on other managed threads', async () => {
    const { last, after } = await agent.exports.otherThread()
    expect(last % 1000).toBe(7)
    expect(after).toBeLessThan(1000)
  })

  it('removes hooks when the script unloads', async () => {
    const other = await loadAgent<HooksAgent>('test/e2e/agents/hooks.ts')
    await other.exports.installForUnload()
    expect(await agent.exports.callTwice(4)).toBe(-1)
    await other.unload()
    expect(await agent.exports.callTwice(4)).toBe(8)
  })
})
