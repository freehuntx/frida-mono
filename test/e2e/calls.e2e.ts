import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { loadAgent, type LoadedAgent } from './support/agent'

/* eslint-disable @typescript-eslint/no-explicit-any -- agent results are checked structurally */
type CallsAgent = Record<
  'primitives' | 'strings' | 'enums' | 'structs' | 'arrays' | 'objects' | 'staticFields' | 'refOut' | 'exceptions' | 'nullable' | 'gc' | 'handles',
  () => Promise<any>
>

const NS = 'FridaMono.Tests'
const point = (X: number, Y: number) => ({ struct: `${NS}.Point`, fields: { X, Y } })
const managed = (type: string, message: string) => ({ managed: true, type, message: `${type}: ${message}`, hasStack: true })

describe('calls', () => {
  let agent: LoadedAgent<CallsAgent>

  beforeAll(async () => {
    agent = await loadAgent<CallsAgent>('test/e2e/agents/calls.ts')
  })

  afterAll(async () => {
    await agent?.unload()
  })

  it('round-trips every primitive type', async () => {
    expect(await agent.exports.primitives()).toEqual({
      not: true,
      nextChar: 'b',
      negI1: -5,
      incU1: 255,
      negI2: -300,
      incU2: 65535,
      negI4: -123456,
      incU4: 4294967295,
      negI8: '-1099511627776n',
      negI8Number: '-7n',
      incU8: '9223372036854775809n',
      halfR4: 1.5,
      halfR8: 0.25,
      addPtr: { pointer: '0x1010' },
      maxLong: '9223372036854775807n',
      maxULong: '18446744073709551615n'
    })
  })

  it('round-trips strings as UTF-16, including null and surrogate pairs', async () => {
    expect(await agent.exports.strings()).toEqual({
      concat: 'foobar',
      emoji: 'héllo 🦊 wörld',
      empty: '',
      nullEcho: null,
      nullLength: -1,
      length: 2,
      constText: 'const'
    })
  })

  it('converts enums from names and numbers, with [Flags] names', async () => {
    const r = await agent.exports.enums()
    expect(r.nextColor).toEqual({ enum: `${NS}.Color`, value: 6, name: 'Blue' })
    expect(r.nextColorNumber).toEqual({ enum: `${NS}.Color`, value: 1, name: '1' })
    expect(r.combine).toEqual({ enum: `${NS}.Access`, value: 3, name: 'Read, Write' })
    expect(r.combineString).toEqual(r.combine)
    expect(r.badName.message).toBe(`${NS}.Color has no constant Purple. Constants: Red, Green, Blue`)
  })

  it('passes and returns structs by value', async () => {
    expect(await agent.exports.structs()).toEqual({
      made: point(100, 4), // changed after AddPoints copied it
      sum: point(13, 24),
      lengthSquared: 113,
      constructed: point(7, 8),
      zero: point(0, 0),
      staticPoint: point(1, 2)
    })
  })

  it('handles arrays in both directions', async () => {
    const r = await agent.exports.arrays()
    expect(r.sum).toBe(10)
    expect(r.split).toEqual({ array: 'System.String[]', items: ['a', 'b', 'c'] })
    expect(r.range).toEqual({ array: 'System.Int32[]', items: [10, 1, 2, 3] })
    expect(r.length).toBe(4)
    expect(r.iterated).toEqual([10, 1, 2, 3])
    expect(r.points).toEqual({ array: `${NS}.Point[]`, items: [point(1, 2), point(3, 4)] })
    expect(r.sumOfManaged).toBe(16)
    expect(r.outOfRange.name).toBe('RangeError')
  })

  it('wraps objects as their runtime class, dispatches virtually and boxes for object parameters', async () => {
    const r = await agent.exports.objects()
    expect(r).toMatchObject({
      animal: { object: `${NS}.Dog` },
      runtimeClass: `${NS}.Dog`,
      isAnimal: true,
      speak: 'Woof',
      describe: 'Rex says Woof',
      getName: 'Rex',
      rename: 'Max',
      legs: 4,
      protectedField: 'Max',
      identityString: 'text',
      identityInt: 5,
      identityDouble: 2.5,
      identityBool: true,
      identityLong: '1099511627776n',
      identityEnum: { enum: `${NS}.Color`, value: 6, name: 'Blue' },
      identityStruct: point(1, 1),
      typeOfInt: 'System.Int32',
      typeOfFloat: 'System.Single',
      typeOfNull: 'null',
      newDog: { object: `${NS}.Dog` }
    })
    expect(r.wrongType).toEqual({ managed: false, name: 'TypeError', message: `Expected ${NS}.Animal, got System.String` })
    expect(r.abstract.message).toBe(`Cannot create an instance of abstract class ${NS}.Shape`)
  })

  it('reads and writes static fields', async () => {
    const r = await agent.exports.staticFields()
    expect(r.before).toEqual({ text: 'static', number: 7 })
    expect(r.after).toEqual({ text: 'changed', number: 8 })
    expect(r.setConst.message).toBe('ConstText is a const and has no storage')
  })

  it('supports ref and out parameters', async () => {
    const r = await agent.exports.refOut()
    expect(r.fill).toEqual({ number: 42, text: 'filled', point: point(5, 6) })
    expect(r.twice).toEqual({ number: 42, text: 'abab' })
    expect(r.tryParse).toEqual({ ok: true, value: 1234 })
    expect(r.notARef.message).toMatch(/is ref: pass Mono\.ref\(value\)$/)
  })

  it('turns managed exceptions into ManagedError, including runtime ones raised by signals', async () => {
    const r = await agent.exports.exceptions()
    expect(r.thrown).toEqual(managed('System.InvalidOperationException', 'boom'))
    expect(r.divide).toMatchObject({ managed: true, type: 'System.DivideByZeroException', hasStack: true })
    expect(r.nullReference).toMatchObject({ managed: true, type: 'System.NullReferenceException', hasStack: true })
    expect(r.arity.message).toBe(`${NS}.Calls:Divide (int,int) takes 2 argument(s), got 1`)
    expect(r.instanceWithoutThis.message).toBe(`${NS}.Animal:Speak () is an instance method: pass the instance`)
  })

  it('maps Nullable<T> to T | null', async () => {
    expect(await agent.exports.nullable()).toEqual({
      doubled: 42,
      nothing: null,
      structHasValue: true,
      structNull: false,
      field: { before: null, set: 5, cleared: null }
    })
  })

  it('keeps wrapped objects valid across full GCs', async () => {
    const r = await agent.exports.gc()
    expect(r.allNamed).toBe(true)
    expect(r.concat).toBe(200_000)
  })

  it('frees GC handles on dispose', async () => {
    expect(await agent.exports.handles()).toEqual({ grew: 50, after: 0 })
  })
})
