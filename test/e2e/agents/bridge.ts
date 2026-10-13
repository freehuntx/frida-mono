/* eslint-disable @typescript-eslint/no-explicit-any -- the bridge is dynamic by design */
import Mono, { EnumValue, ManagedError, MArray, OverloadError } from '../../../src'

function check(fn: () => unknown): unknown {
  try {
    return plain(fn())
  } catch (e) {
    const error = e as Error
    return { threw: error.name, message: error.message.split('\n')[0], managedType: e instanceof ManagedError ? e.type : undefined, overload: e instanceof OverloadError }
  }
}

function plain(value: unknown): unknown {
  if (typeof value === 'bigint') return `${value}n`
  if (value instanceof EnumValue) return { enum: value.name, value: value.valueOf() }
  if (value instanceof MArray) return value.toArray().map(plain)
  if (Array.isArray(value)) return value.map(plain)
  if (typeof value === 'function' || (typeof value === 'object' && value !== null && Object.getPrototypeOf(value) !== Object.prototype)) return String(value)
  if (typeof value === 'object' && value !== null) return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plain(v)]))
  return value
}

function cases(): Record<string, () => unknown> {
  const { FridaMono, System } = Mono.namespaces
  const T = FridaMono.Tests
  const dog = new T.Dog('Rex')
  const List = System.Collections.Generic.List
  const StringList = List.$of(System.String)

  return {
    // classes, statics, inheritance
    staticCall: () => T.Smoke.Answer(),
    viaUse: () => Mono.use('FridaMono.Tests.Smoke').Answer(),
    viaUseAssembly: () => Mono.use('TestLib', 'FridaMono.Tests.Smoke').Answer(),
    classString: () => String(T.Dog),
    staticField: () => T.Animal.MaxLegs,
    staticInherited: () => String(T.Dog.Create('Pup')),
    staticFieldWrite: () => {
      const before = T.Calls.StaticNumber
      T.Calls.StaticNumber = 99
      const after = T.Calls.StaticNumber
      T.Calls.StaticNumber = before
      return [before, after]
    },
    nestedClass: () => {
      const collar = new T.Dog.Collar()
      collar.Tag = 'blue'
      return [String(T.Dog.Collar), collar.Tag]
    },

    // instances
    virtualCall: () => dog.Speak(),
    property: () => dog.Name,
    propertyWrite: () => {
      dog.Name = 'Max'
      const name = dog.Name
      dog.Name = 'Rex'
      return name
    },
    readonlyField: () => dog.Legs,
    autoProperty: () => dog.Age,
    backingField: () => dog.$field('<Age>k__BackingField'),
    interfaceCall: () => dog.Greet('you'),
    indexer: () => dog.$item(3),
    instanceofClass: () => dog instanceof T.Dog && dog instanceof T.Animal && dog instanceof System.Object,
    instanceofInterface: () => dog instanceof T.IGreeter,
    notInstance: () => dog instanceof T.Shape,
    templateString: () => `${dog}`,
    runtimeClass: () => String(T.Calls.MakeAnimal('Bo').$class),
    castAndIs: () => {
      const animal = T.Calls.MakeAnimal('Bo')
      return [animal.$is(T.Dog), animal.$cast(T.Animal).Speak(), animal.$is(T.Shape)]
    },
    equals: () => {
      const a = T.Calls.Identity(dog)
      return [a.$equals(dog), dog.$equals(new T.Dog('Rex'))]
    },
    prototypeChain: () => Object.getPrototypeOf(T.Dog.prototype) === T.Animal.prototype && Object.getPrototypeOf(T.Dog) === T.Animal,
    nullPrototype: () => ['hasOwnProperty', 'toString', 'constructor'].map((k) => (dog as any)[k] === undefined),

    // assignment rules
    assignMethod: () => {
      dog.Speak = () => 'x'
    },
    assignUnknown: () => {
      dog.Nope = 1
    },
    assignReadonlyProperty: () => {
      const p = new T.Point(1, 2)
      p.LengthSquared = 3
    },
    callWithoutNew: () => (T.Dog as any)('x'),

    // overloads
    pickInt: () => T.Overloads.Pick(1),
    pickDouble: () => T.Overloads.Pick(1.5),
    pickString: () => T.Overloads.Pick('x'),
    pickTwo: () => T.Overloads.Pick(1, 2),
    pickDog: () => T.Overloads.Pick(dog),
    pickAnimal: () => T.Overloads.Pick(T.Animal.Create('a')),
    pickBools: () => T.Overloads.Pick(true, false),
    pickForced: () => T.Overloads.Pick.$overload('double')(1),
    pickForcedFullName: () => T.Overloads.Pick.$overload('System.String')('s'),
    overloads: () => T.Overloads.Pick.$overloads,
    noOverload: () => T.Overloads.Pick(true),
    mathMax: () => [System.Math.Max(1, 2), System.Math.Max(1.5, 2)],
    stringBuilder: () => String(new System.Text.StringBuilder('abc', 64).Append('def')),
    ctorOverload: () => [new T.Animal('a').Legs, new T.Animal('b', 3).Legs],

    // structs and enums
    struct: () => {
      const p = new T.Point(3, 4)
      p.X = 6
      return [p.LengthSquared, p.$value]
    },
    structArgument: () => T.Calls.AddPoints(new T.Point(1, 2), { X: 10, Y: 20 }).$value,
    structDefault: () => new T.Point().$value,
    enumConstant: () => T.Color.Blue,
    enumCall: () => T.Calls.NextColor(T.Color.Green),
    enumByName: () => T.Calls.Combine('Read', T.Access.Write),

    // generics
    genericClass: () => {
      const list = new StringList()
      list.Add('a')
      list.Add('b')
      return [list.Count, [...list], list.$item(1)]
    },
    genericByString: () => Mono.use('System.Collections.Generic.List<System.String>') === StringList,
    genericByAlias: () => String(Mono.use('System.Collections.Generic.Dictionary<string, int>')),
    openGenericNew: () => new List(),
    customGeneric: () => new (T.Box.$of(System.Int32))(5).Get(),
    genericMethodInferred: () => [T.Generics.Echo(5), T.Generics.Echo('s'), String(T.Generics.Echo(dog))],
    genericMethodExplicit: () => [T.Generics.Empty.$of(System.Int32)().length, T.Generics.NameOf.$of(T.Dog)()],
    genericMethodNotInferable: () => T.Generics.Empty(),
    genericArgument: () => {
      const list = new StringList()
      list.Add('x')
      return T.Generics.CountOf.$of(System.String)(list)
    },

    // ref/out, exceptions, System.Type
    refOut: () => {
      const out = Mono.ref<number>()
      return [System.Int32.TryParse('42', out), out.value]
    },
    managedException: () => T.Calls.Throw('boom'),
    classAsType: () => T.Calls.TypeName(T.Dog),
    typeObject: () => T.Dog.$type.FullName,
    introspection: () => [T.Overloads.$methods.length > 0, T.Animal.$fields.map((f: any) => f.name), T.Animal.$properties.map((p: any) => p.name)],
    arrays: () => [...T.Calls.Range(3)],
    namespaceString: () => String(System.Collections),
    notThenable: () => (System as any).then === undefined
  }
}

function rate(fn: () => unknown, iterations: number): number {
  const start = Date.now()
  for (let i = 0; i < iterations; i++) fn()
  return Math.round((iterations / Math.max(Date.now() - start, 1)) * 1000)
}

rpc.exports = {
  bench() {
    return Mono.performNow(() => {
      const T = Mono.namespaces.FridaMono.Tests
      const dog = new T.Dog('Rex')
      const answer = Mono.use('FridaMono.Tests.Smoke').$class.method('Answer')
      return {
        rawInvoke: rate(() => answer.invoke(null), 20000),
        staticCall: rate(() => T.Smoke.Answer(), 20000),
        overloaded: rate(() => T.Overloads.Pick(1), 20000),
        propertyGet: rate(() => dog.Name, 20000),
        fieldGet: rate(() => dog.Legs, 20000),
        virtualCall: rate(() => dog.Speak(), 20000),
        newObject: rate(() => new T.Dog('x'), 5000)
      }
    })
  },

  run() {
    return Mono.performNow(() => Object.fromEntries(Object.entries(cases()).map(([name, fn]) => [name, check(fn)])))
  }
}
