import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { loadAgent, type LoadedAgent } from './support/agent'

/* eslint-disable @typescript-eslint/no-explicit-any -- agent results are checked structurally */
interface MetaAgent {
  assembly(): Promise<any>
  describe(name: string): Promise<any>
  lookups(): Promise<any>
  types(): Promise<any>
  everything(): Promise<{ classes: number; members: number }>
}

const NS = 'FridaMono.Tests'

describe('meta', () => {
  let agent: LoadedAgent<MetaAgent>

  beforeAll(async () => {
    agent = await loadAgent<MetaAgent>('test/e2e/agents/meta.ts')
  })

  afterAll(async () => {
    await agent?.unload()
  })

  it('enumerates the fixture assembly', async () => {
    const assembly = await agent.exports.assembly()
    expect(assembly.name).toBe('TestLib')
    expect(assembly.fullName).toMatch(/^TestLib, Version=0\.0\.0\.0, Culture=neutral, PublicKeyToken=null$/)
    expect(assembly.classes).toEqual(
      expect.arrayContaining(['Smoke', 'Color', 'Access', 'IGreeter', 'Point', 'Animal', 'Dog', 'Dog+Collar', 'Shape', 'Overloads', 'Box<T>', 'Holder'].map((n) => `${NS}.${n}`))
    )
  })

  it('describes a class: fields, methods, properties, events', async () => {
    const animal = await agent.exports.describe('Animal')
    expect(animal).toMatchObject({ name: 'Animal', namespace: NS, parent: 'System.Object', kind: 'class', sealed: false, abstract: false })
    expect(animal.fields).toEqual(
      expect.arrayContaining([
        { name: 'MaxLegs', type: 'System.Int32', static: true, access: 'public', literal: true, readonly: false },
        { name: 'Count', type: 'System.Int32', static: true, access: 'public', literal: false, readonly: false },
        { name: 'name', type: 'System.String', static: false, access: 'protected', literal: false, readonly: false },
        { name: 'Legs', type: 'System.Int32', static: false, access: 'public', literal: false, readonly: true },
        expect.objectContaining({ name: '<Age>k__BackingField', access: 'private' })
      ])
    )
    const ctors = animal.methods.filter((m: any) => m.name === '.ctor')
    expect(ctors.map((m: any) => m.params.map((p: any) => `${p.type} ${p.name}`))).toEqual([['System.String name'], ['System.String name', 'System.Int32 legs']])
    expect(animal.methods.find((m: any) => m.name === 'Create')).toMatchObject({ static: true, returns: `${NS}.Animal` })
    expect(animal.methods.find((m: any) => m.name === 'Speak')).toMatchObject({ virtual: true, static: false })
    expect(animal.methods.find((m: any) => m.name === 'OnRenamed')).toMatchObject({ access: 'internal' })
    expect(animal.properties).toEqual([
      { name: 'Name', type: 'System.String', static: false, get: true, set: true, index: [] },
      { name: 'Age', type: 'System.Int32', static: false, get: true, set: true, index: [] },
      { name: 'Item', type: 'System.Int32', static: false, get: true, set: false, index: ['System.Int32'] }
    ])
    expect(animal.events).toEqual([{ name: 'Renamed', type: 'System.EventHandler', static: false }])
  })

  it('describes inheritance, interfaces and nesting', async () => {
    const dog = await agent.exports.describe('Dog')
    expect(dog).toMatchObject({ parent: `${NS}.Animal`, sealed: true, interfaces: [`${NS}.IGreeter`], nested: [`${NS}.Dog+Collar`] })
    const collar = await agent.exports.describe('Dog+Collar')
    expect(collar).toMatchObject({ name: 'Collar', fullName: `${NS}.Dog+Collar`, declaringClass: `${NS}.Dog` })
    expect(await agent.exports.describe('Shape')).toMatchObject({ abstract: true })
    expect(await agent.exports.describe('IGreeter')).toMatchObject({ kind: 'interface' })
  })

  it('describes structs, enums and generic definitions', async () => {
    expect(await agent.exports.describe('Point')).toMatchObject({ kind: 'struct', parent: 'System.ValueType' })
    const access = await agent.exports.describe('Access')
    expect(access.kind).toBe('enum')
    expect(access.fields.filter((f: any) => f.literal).map((f: any) => f.name)).toEqual(['None', 'Read', 'Write'])
    const box = await agent.exports.describe('Box`1')
    expect(box).toMatchObject({ name: 'Box`1', fullName: `${NS}.Box<T>`, genericDefinition: true, genericInstance: false })
  })

  it('looks up classes and members', async () => {
    const r = await agent.exports.lookups()
    expect(r).toMatchObject({
      bySimpleName: `${NS}.Dog`,
      nestedPlus: `${NS}.Dog+Collar`,
      nestedSlash: `${NS}.Dog+Collar`,
      missing: null,
      corlib: 'mscorlib',
      inherited: `${NS}.Animal:Create (string)`,
      inheritedField: `${NS}.Animal`,
      inheritedProperty: `${NS}.Animal`,
      inheritedEvent: `${NS}.Animal`,
      speakOverloads: [`${NS}.Dog:Speak ()`, `${NS}.Animal:Speak ()`],
      pickOneParam: `${NS}.Overloads:Pick (bool,bool)`, // first declared overload with 2 parameters
      isSubclass: true,
      implements: true,
      assignable: true,
      notAssignable: false,
      hierarchy: [`${NS}.Dog`, `${NS}.Animal`, 'System.Object'],
      byDescMissing: null
    })
    expect(r.byDesc).toMatchObject({ name: 'Pick', static: true, returns: 'System.String', params: [{ type: 'System.Int32' }, { type: 'System.Int32' }] })
  })

  it('reads types: generics, arrays, structs, enums, ref/out', async () => {
    const t = await agent.exports.types()
    expect(t.names).toMatchObject({ name: 'System.Collections.Generic.List<System.String>', typeEnum: 'GENERICINST', genericInstance: true })
    expect(t.intBox).toMatchObject({ class: `${NS}.Box<System.Int32>`, genericInstance: true })
    expect(t.numbers).toMatchObject({ name: 'System.Int32[]', typeEnum: 'SZARRAY', rank: 1 })
    expect(t.numbersElement).toBe('System.Int32')
    expect(t.origin).toMatchObject({ typeEnum: 'VALUETYPE', valueType: true })
    expect(t.pointSize).toBe(8)
    expect(t.accessBase).toBe('System.Byte')
    expect(t.colorBase).toBe('System.Int32')
    expect(t.swap).toEqual([
      { name: 'a', type: 'System.Int32&', byRef: true, out: false },
      { name: 'b', type: 'System.Int32&', byRef: true, out: false }
    ])
    expect(t.tryDouble).toEqual([
      { name: 'x', byRef: false, out: false },
      { name: 'result', byRef: true, out: true }
    ])
    expect(t.boxValue).toMatchObject({ name: 'T', typeEnum: 'VAR' })
    expect(t.mapReturn).toMatchObject({ name: 'U', typeEnum: 'MVAR' })
    expect(t.interned).toBe(true)
  })

  it('walks every class and member of every loaded assembly', async () => {
    const { classes, members } = await agent.exports.everything()
    console.log(`${classes} classes, ${members} members`)
    expect(classes).toBeGreaterThan(1000)
    expect(members).toBeGreaterThan(10000)
  })
})
