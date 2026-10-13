import { describe, expect, it } from 'vitest'
import { IMPOSSIBLE, resolveOverload, scoreArgument, type ArgumentInspector, type ParamKind } from '../../src/bridge/overload'

// Fake classes: a tiny hierarchy Dog → Animal → Object, plus an interface.
const Object_ = { name: 'Object', chain: [] as unknown[] }
const Animal = { name: 'Animal', chain: [Object_] }
const Dog = { name: 'Dog', chain: [Animal, Object_] }
const IGreeter = { name: 'IGreeter', chain: [] }
type Fake = typeof Object_

class Wrapped {
  constructor(readonly klass: Fake) {}
}
class FakeRef {
  constructor(readonly value: unknown) {}
}

const inspector: ArgumentInspector = {
  classOf: (v) => (v instanceof Wrapped ? v.klass : undefined),
  isClassWrapper: () => false,
  isRef: (v): v is { value: unknown } => v instanceof FakeRef,
  isEnumValue: () => false,
  distance(from, to) {
    const f = from as Fake
    if (f === to) return 0
    const i = f.chain.indexOf(to)
    if (i >= 0) return i + 1
    return to === IGreeter && f === Dog ? 5 : -1
  },
  acceptsType: () => false,
  acceptsBoxed: (klass) => klass === Object_,
  isDelegate: () => false
}

const int: ParamKind = { kind: 'integer', name: 'int' }
const long: ParamKind = { kind: 'integer', name: 'long' }
const byte: ParamKind = { kind: 'integer', name: 'byte' }
const double: ParamKind = { kind: 'double' }
const float: ParamKind = { kind: 'float' }
const string: ParamKind = { kind: 'string' }
const object: ParamKind = { kind: 'reference', class: Object_ }
const animal: ParamKind = { kind: 'reference', class: Animal }
const dog: ParamKind = { kind: 'reference', class: Dog }

function pick(candidates: Record<string, ParamKind[]>, ...args: unknown[]) {
  const result = resolveOverload(
    Object.entries(candidates).map(([method, params]) => ({ method, params })),
    args,
    inspector
  )
  return result.ok ? result.method : result.reason
}

describe('overload resolution', () => {
  const max = { 'int,int': [int, int], 'long,long': [long, long], 'double,double': [double, double], 'float,float': [float, float] }

  it('prefers int for integers and double for fractions, like C#', () => {
    expect(pick(max, 1, 2)).toBe('int,int')
    expect(pick(max, 1.5, 2)).toBe('double,double')
    expect(pick(max, 2 ** 40, 1)).toBe('long,long')
    expect(pick(max, 1n, 2n)).toBe('long,long')
  })

  it('checks integer ranges', () => {
    expect(scoreArgument(255, byte, inspector)).toBeGreaterThan(0)
    expect(scoreArgument(256, byte, inspector)).toBe(IMPOSSIBLE)
    expect(scoreArgument(-1, byte, inspector)).toBe(IMPOSSIBLE)
    expect(scoreArgument(1.5, int, inspector)).toBe(IMPOSSIBLE)
  })

  it('prefers the most derived class and falls back to object', () => {
    const overloads = { animal: [animal], dog: [dog], object: [object] }
    expect(pick(overloads, new Wrapped(Dog))).toBe('dog')
    expect(pick(overloads, new Wrapped(Animal))).toBe('animal')
    expect(pick(overloads, 'text')).toBe('object')
    expect(pick({ animal: [animal] }, new Wrapped(Object_))).toBe('none')
  })

  it('matches arity, null and ref arguments', () => {
    expect(pick({ one: [string], two: [string, string] }, 'a', 'b')).toBe('two')
    expect(pick({ s: [string], i: [int] }, null)).toBe('s')
    const byRefInt: ParamKind = { kind: 'byref', inner: int }
    expect(pick({ out: [string, byRefInt], plain: [string, int] }, 's', new FakeRef(undefined))).toBe('out')
    expect(pick({ out: [string, byRefInt] }, 's', 5)).toBe('none')
  })

  it('reports ties as ambiguous', () => {
    expect(pick({ a: [animal, dog], b: [dog, animal] }, new Wrapped(Dog), new Wrapped(Dog))).toBe('ambiguous')
  })

  it('maps null to Nullable and plain objects to structs', () => {
    const nullableInt: ParamKind = { kind: 'nullable', inner: int }
    expect(pick({ n: [nullableInt], d: [double] }, null)).toBe('n')
    expect(pick({ n: [nullableInt] }, 5)).toBe('n')
    expect(pick({ s: [{ kind: 'struct', class: {} }], o: [string] }, { X: 1 })).toBe('s')
  })
})
