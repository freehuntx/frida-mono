import { describe, expect, it } from 'vitest'
import { emitCs } from '../../src/tools/emit-cs'
import { emitDts } from '../../src/tools/emit-dts'
import type { DumpModel, MethodModel, TypeModel, TypeRef } from '../../src/tools/model'

const int: TypeRef = { kind: 'primitive', name: 'int' }
const long: TypeRef = { kind: 'primitive', name: 'long' }
const string: TypeRef = { kind: 'primitive', name: 'string' }
const ref = (key: string, shape: 'class' | 'struct' | 'enum' = 'class', args: TypeRef[] = []): TypeRef => ({ kind: 'type', key, args, shape })

function type(partial: Partial<TypeModel> & Pick<TypeModel, 'key' | 'name'>): TypeModel {
  return {
    namespace: 'Game',
    declaringType: null,
    kind: 'class',
    access: 'public',
    abstract: false,
    sealed: false,
    genericParams: [],
    parent: null,
    interfaces: [],
    enumValues: [],
    fields: [],
    properties: [],
    methods: [],
    constructors: [],
    events: [],
    ...partial
  }
}

function method(name: string, params: TypeRef[], returns: TypeRef, extra: Partial<MethodModel> = {}): MethodModel {
  return {
    name,
    static: false,
    access: 'public',
    virtual: false,
    abstract: false,
    genericParams: [],
    params: params.map((t, i) => ({ name: `p${i}`, type: t, out: false })),
    returns,
    ...extra
  }
}

const model: DumpModel = {
  runtime: '6.12.0',
  assemblies: ['Game'],
  types: [
    type({
      key: 'Game.Entity',
      name: 'Entity',
      fields: [{ name: 'Id', static: false, access: 'public', readonly: true, literal: false, type: long }],
      methods: [method('Hit', [int], { kind: 'void' })]
    }),
    type({
      key: 'Game.Player',
      name: 'Player',
      parent: ref('Game.Entity'),
      constructors: [method('.ctor', [string], { kind: 'void' })],
      fields: [{ name: 'Id', static: false, access: 'private', readonly: false, literal: false, type: string }],
      methods: [method('Hit', [string], { kind: 'void' }), method('Spawn', [ref('Game.Vec', 'struct')], ref('Game.Player'), { static: true })],
      events: [{ name: 'Died', static: false, type: null }]
    }),
    type({ key: 'Game.Player+Stats', name: 'Stats', namespace: '', declaringType: 'Game.Player', access: 'nested' }),
    type({
      key: 'Game.Vec',
      name: 'Vec',
      kind: 'struct',
      fields: [{ name: 'X', static: false, access: 'public', readonly: false, literal: false, type: { kind: 'primitive', name: 'float' } }]
    }),
    type({
      key: 'Game.Mode',
      name: 'Mode',
      kind: 'enum',
      enumValues: [
        { name: 'Easy', value: '0' },
        { name: 'Hard', value: '1' }
      ]
    }),
    type({ key: 'Game.Box', name: 'Box', constructors: [method('.ctor', [], { kind: 'void' })] }),
    type({ key: 'Game.Box`1', name: 'Box', genericParams: ['T'], methods: [method('Get', [], { kind: 'generic', name: 'T' })] })
  ]
}

describe('emitDts', () => {
  const dts = emitDts(model)

  it('augments MonoNamespaces and MonoTypes', () => {
    expect(dts).toContain("declare module 'frida-mono' {")
    expect(dts).toContain('    Game: typeof __mono.Game')
    expect(dts).toContain('    "Game.Player+Stats": typeof __mono.Game.Player.Stats')
  })

  it('extends the managed parent and merges inherited overloads into one method type', () => {
    expect(dts).toContain('class Player extends __mono.Game.Entity {')
    expect(dts).toContain('Hit: $MonoMethod<{ (p0: string | null): void; (p0: number): void; }>')
  })

  it('types members hiding an ancestor member differently as any', () => {
    expect(dts).toMatch(/class Player[\s\S]*?\n {6}Id: any/)
  })

  it('maps parameter and result types the way the marshaller converts them', () => {
    expect(dts).toContain('readonly Id: bigint')
    expect(dts).toContain('static Spawn: $MonoMethod<{ (p0: __mono.Game.Vec | { X?: number }): __mono.Game.Player; }>')
    expect(dts).toContain('readonly Died: $MonoEvent')
  })

  it('emits enums, nested classes and arity suffixes for clashing generic names', () => {
    expect(dts).toContain('class Mode extends $EnumValue {')
    expect(dts).toContain('static readonly Hard: __mono.Game.Mode')
    expect(dts).toContain('namespace Player {')
    expect(dts).toContain('class Box_1<T = any> extends $MonoObject {')
    expect(dts).toContain('Get: $MonoMethod<{ (): T; }>')
  })
})

describe('emitCs', () => {
  it('lists types like C#', () => {
    const cs = emitCs(model)
    expect(cs).toContain('public class Player : Game.Entity')
    expect(cs).toContain('public static Game.Player Spawn(Game.Vec p0);')
    expect(cs).toContain('public enum Mode')
  })
})
