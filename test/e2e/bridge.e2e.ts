import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { loadAgent, type LoadedAgent } from './support/agent'

const NS = 'FridaMono.Tests'
const threw = (name: string, message?: string) => expect.objectContaining({ threw: name, ...(message === undefined ? {} : { message }) })

describe('bridge', () => {
  let agent: LoadedAgent<{ run(): Promise<Record<string, unknown>>; bench(): Promise<Record<string, number>> }>
  let r: Record<string, unknown>

  beforeAll(async () => {
    agent = await loadAgent('test/e2e/agents/bridge.ts')
    r = await agent.exports.run()
  })

  afterAll(async () => {
    await agent?.unload()
  })

  it('reaches classes through namespaces and Mono.use, with static members and nesting', () => {
    expect(r).toMatchObject({
      staticCall: 42,
      viaUse: 42,
      viaUseAssembly: 42,
      classString: `class ${NS}.Dog`,
      staticField: 4,
      staticInherited: `${NS}.Animal`,
      staticFieldWrite: [7, 99],
      nestedClass: [`class ${NS}.Dog+Collar`, 'blue'],
      namespaceString: 'namespace System.Collections',
      notThenable: true
    })
  })

  it('exposes instance members: virtual methods, properties, fields, indexers', () => {
    expect(r).toMatchObject({
      virtualCall: 'Woof',
      property: 'Rex',
      propertyWrite: 'Max',
      readonlyField: 4,
      autoProperty: 0,
      backingField: 0,
      interfaceCall: 'Hi you',
      indexer: 12,
      templateString: `${NS}.Dog`,
      runtimeClass: `${NS}.Dog`
    })
  })

  it('mirrors the managed hierarchy in prototypes and instanceof, with null-prototype roots', () => {
    expect(r).toMatchObject({
      instanceofClass: true,
      instanceofInterface: true,
      notInstance: false,
      castAndIs: [true, 'Woof', false],
      equals: [true, false],
      prototypeChain: true,
      nullPrototype: [true, true, true]
    })
  })

  it('rejects assignments that would not do what they look like', () => {
    expect(r.assignMethod).toEqual(threw('TypeError', `Assigning ${NS}.Dog.Speak doesn't hook it. Use .Speak.$override(fn) instead`))
    expect(r.assignUnknown).toEqual(threw('TypeError', `${NS}.Dog has no instance member Nope`))
    expect(r.assignReadonlyProperty).toEqual(threw('TypeError', `Property ${NS}.Point.LengthSquared is read-only`))
    expect(r.callWithoutNew).toEqual(threw('TypeError', `Class constructor ${NS}.Dog cannot be invoked without 'new'`))
  })

  it('resolves overloads from the arguments', () => {
    expect(r).toMatchObject({
      pickInt: 'int',
      pickDouble: 'double',
      pickString: 'string',
      pickTwo: 'int,int',
      pickDog: 'Dog',
      pickAnimal: 'Animal',
      pickBools: 'bool,bool',
      pickForced: 'double',
      pickForcedFullName: 'string',
      mathMax: [2, 2],
      stringBuilder: 'abcdef',
      ctorOverload: [4, 3]
    })
    expect(r.overloads).toHaveLength(7)
    expect(r.noOverload).toEqual(expect.objectContaining({ threw: 'OverloadError', overload: true, message: `No overload of ${NS}.Overloads.Pick(boolean) matches` }))
  })

  it('handles structs and enums', () => {
    expect(r).toMatchObject({
      struct: [52, { X: 6, Y: 4 }],
      structArgument: { X: 11, Y: 22 },
      structDefault: { X: 0, Y: 0 },
      enumConstant: { enum: 'Blue', value: 6 },
      enumCall: { enum: 'Blue', value: 6 },
      enumByName: { enum: 'Read, Write', value: 3 }
    })
  })

  it('supports generic classes and methods', () => {
    expect(r).toMatchObject({
      genericClass: [2, ['a', 'b'], 'b'],
      genericByString: true,
      genericByAlias: 'class System.Collections.Generic.Dictionary<System.String,System.Int32>',
      customGeneric: 5,
      genericMethodInferred: [5, 's', `${NS}.Dog`],
      genericMethodExplicit: [0, `${NS}.Dog`],
      genericArgument: 1
    })
    expect(r.openGenericNew).toEqual(threw('MonoError', 'System.Collections.Generic.List<T> is an open generic type: close it first with .$of(...types)'))
    expect(r.genericMethodNotInferable).toEqual(threw('MonoError'))
  })

  it('handles ref/out, exceptions, System.Type arguments and introspection', () => {
    expect(r).toMatchObject({
      refOut: [true, 42],
      classAsType: `${NS}.Dog`,
      typeObject: `${NS}.Dog`,
      arrays: [0, 1, 2],
      introspection: [true, expect.arrayContaining(['MaxLegs', 'Count', 'name', 'Legs', '<Age>k__BackingField', 'Renamed']), ['Name', 'Age', 'Item']]
    })
    expect(r.managedException).toEqual(expect.objectContaining({ threw: 'ManagedError', managedType: 'System.InvalidOperationException' }))
  })

  it('benchmark (calls per second, logged only)', async () => {
    const result = await agent.exports.bench()
    console.log(
      Object.entries(result)
        .map(([name, perSecond]) => `${name}: ${perSecond.toLocaleString('en')}/s`)
        .join(', ')
    )
  })
})
