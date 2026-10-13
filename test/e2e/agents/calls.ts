import Mono, { EnumValue, MArray, ManagedError, ManagedObject, StructView, type Class, type Method } from '../../../src'

const NS = 'FridaMono.Tests'

function cls(name: string): Class {
  return Mono.class(`${NS}.${name}`)
}

function method(klass: string, name: string, paramCount = -1): Method {
  const m = cls(klass).method(name, paramCount)
  if (m === null) throw new Error(`${klass}.${name} not found`)
  return m
}

/** The raw low-level value behind a bridge instance (this agent tests the layer below the bridge). */
function raw<T>(value: unknown): T {
  return (Mono.unwrap(value) ?? value) as T
}

/** Makes results JSON-safe and keeps the JS type visible in assertions. */
function plain(value: unknown): unknown {
  value = raw(value)
  if (typeof value === 'bigint') return `${value}n`
  if (value instanceof EnumValue) return { enum: value.class.fullName, value: plain(value.value), name: value.name }
  if (value instanceof StructView) return { struct: value.class.fullName, fields: plain(value.toJSON()) }
  if (value instanceof MArray) return { array: value.class.fullName, items: value.toArray().map(plain) }
  if (value instanceof ManagedObject) return { object: value.class.fullName, string: value.toString() }
  if (value instanceof NativePointer) return { pointer: value.toString() }
  if (Array.isArray(value)) return value.map(plain)
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plain(v)]))
  return value
}

function call(name: string, ...args: unknown[]): unknown {
  return plain(method('Calls', name, args.length).invoke(null, ...args))
}

function error(fn: () => unknown): unknown {
  try {
    fn()
    return null
  } catch (e) {
    if (e instanceof ManagedError) return { managed: true, type: e.type, message: e.message, hasStack: e.managedStack.includes(' at ') }
    return { managed: false, name: (e as Error).name, message: (e as Error).message }
  }
}

rpc.exports = {
  primitives() {
    return Mono.performNow(() => ({
      not: call('Not', false),
      nextChar: call('NextChar', 'a'),
      negI1: call('NegI1', 5),
      incU1: call('IncU1', 254),
      negI2: call('NegI2', 300),
      incU2: call('IncU2', 65534),
      negI4: call('NegI4', 123456),
      incU4: call('IncU4', 4294967294),
      negI8: call('NegI8', 1099511627776n),
      negI8Number: call('NegI8', 7),
      incU8: call('IncU8', 9223372036854775808n),
      halfR4: call('HalfR4', 3),
      halfR8: call('HalfR8', 0.5),
      addPtr: call('AddPtr', ptr(0x1000), 0x10),
      maxLong: call('MaxLong'),
      maxULong: call('MaxULong')
    }))
  },

  strings() {
    return Mono.performNow(() => ({
      concat: call('Concat', 'foo', 'bar'),
      emoji: call('Echo', 'héllo 🦊 wörld'),
      empty: call('Echo', ''),
      nullEcho: call('Echo', null),
      nullLength: call('Length', null),
      length: call('Length', '🦊'),
      constText: cls('Calls').field('ConstText')?.getValue()
    }))
  },

  enums() {
    return Mono.performNow(() => ({
      nextColor: call('NextColor', 'Green'),
      nextColorNumber: call('NextColor', 0),
      combine: call('Combine', 'Read', 'Write'),
      combineString: call('Combine', 'Read, Write', 0),
      badName: error(() => call('NextColor', 'Purple'))
    }))
  },

  structs() {
    return Mono.performNow(() => {
      const made = raw<StructView>(method('Calls', 'MakePoint').invoke(null, 3, 4))
      const sum = raw<StructView>(method('Calls', 'AddPoints').invoke(null, made, { X: 10, Y: 20 }))
      made.set('X', 100)
      const ctor = cls('Point').methodsNamed('.ctor')[0] as Method
      const constructed = raw<StructView>(cls('Point').construct(ctor, 7, 8))
      return {
        made: plain(made),
        sum: plain(sum),
        lengthSquared: plain(method('Point', 'get_LengthSquared').invoke(constructed)),
        constructed: plain(constructed),
        zero: plain(cls('Point').construct()),
        staticPoint: plain(cls('Calls').field('StaticPoint')?.getValue())
      }
    })
  },

  arrays() {
    return Mono.performNow(() => {
      const range = raw<MArray>(method('Calls', 'Range').invoke(null, 4))
      range.set(0, 10)
      return {
        sum: call('SumArray', [1, 2, 3, 4]),
        split: call('Split', 'a,b,c'),
        range: plain(range),
        length: range.length,
        iterated: [...range],
        points: call('Points'),
        sumOfManaged: call('SumArray', range),
        outOfRange: error(() => range.get(9))
      }
    })
  },

  objects() {
    return Mono.performNow(() => {
      const animal = raw<ManagedObject>(method('Calls', 'MakeAnimal').invoke(null, 'Rex'))
      const name = cls('Animal').property('Name')
      return {
        animal: plain(animal),
        runtimeClass: animal.class.fullName,
        isAnimal: animal.isInstanceOf(cls('Animal')),
        // Animal.Speak is virtual: invoking it on a Dog runs Dog.Speak.
        speak: method('Animal', 'Speak').invoke(animal),
        describe: call('Describe', animal),
        getName: name?.getter?.invoke(animal),
        rename: (name?.setter?.invoke(animal, 'Max'), name?.getter?.invoke(animal)),
        legs: cls('Animal').field('Legs')?.getValue(animal),
        protectedField: cls('Animal').field('name')?.getValue(animal),
        identityString: call('Identity', 'text'),
        identityInt: call('Identity', 5),
        identityDouble: call('Identity', 2.5),
        identityBool: call('Identity', true),
        identityLong: call('Identity', 1099511627776n),
        identityEnum: call('Identity', new EnumValue(cls('Color'), 6)),
        identityStruct: call('Identity', method('Calls', 'MakePoint').invoke(null, 1, 1)),
        typeOfInt: call('TypeOf', 5),
        typeOfFloat: call('TypeOf', Mono.box(Mono.class('System.Single'), 1.5)),
        typeOfNull: call('TypeOf', null),
        wrongType: error(() => call('Describe', 'not an animal')),
        newDog: plain(cls('Dog').construct(cls('Dog').methodsNamed('.ctor')[0] as Method, 'Fido')),
        abstract: error(() => cls('Shape').construct())
      }
    })
  },

  staticFields() {
    return Mono.performNow(() => {
      const text = cls('Calls').field('StaticText')
      const number = cls('Calls').field('StaticNumber')
      const before = { text: text?.getValue(), number: number?.getValue() }
      text?.setValue('changed')
      number?.setValue((number.getValue() as number) + 1)
      const after = { text: text?.getValue(), number: number?.getValue() }
      text?.setValue('static')
      number?.setValue(7)
      return { before, after, setConst: error(() => cls('Calls').field('ConstText')?.setValue('x')) }
    })
  },

  refOut() {
    return Mono.performNow(() => {
      const number = Mono.ref<number>()
      const text = Mono.ref<string>()
      const point = Mono.ref<StructView>()
      method('Calls', 'Fill').invoke(null, number, text, point)
      const n = Mono.ref(21)
      const t = Mono.ref('ab')
      method('Calls', 'Twice').invoke(null, n, t)
      const parsed = Mono.ref<number>()
      const ok = Mono.class('System.Int32').method('TryParse', 2)?.invoke(null, '1234', parsed)
      return {
        fill: plain({ number: number.value, text: text.value, point: point.value }),
        twice: { number: n.value, text: t.value },
        tryParse: { ok, value: parsed.value },
        notARef: error(() => method('Calls', 'Twice').invoke(null, 1, 'x'))
      }
    })
  },

  exceptions() {
    return Mono.performNow(() => ({
      thrown: error(() => call('Throw', 'boom')),
      divide: error(() => call('Divide', 1, 0)),
      nullReference: error(() => call('Describe', null)),
      arity: error(() => method('Calls', 'Divide').invoke(null, 1)),
      instanceWithoutThis: error(() => method('Animal', 'Speak').invoke(null))
    }))
  },

  nullable() {
    return Mono.performNow(() => {
      const field = cls('Calls').field('NullableField')
      const before = field?.getValue()
      field?.setValue(5)
      const set = field?.getValue()
      field?.setValue(null)
      return {
        doubled: call('MaybeDouble', 21),
        nothing: call('MaybeDouble', null),
        structHasValue: call('HasValue', { X: 1, Y: 2 }),
        structNull: call('HasValue', null),
        field: { before, set, cleared: field?.getValue() }
      }
    })
  },

  gc() {
    // Objects held only by wrappers must survive full (moving, under SGen) collections.
    return Mono.performNow(() => {
      const animals = Array.from({ length: 200 }, (_, i) => raw<ManagedObject>(method('Calls', 'MakeAnimal').invoke(null, `a${i}`)))
      for (let i = 0; i < 3; i++) Mono.api.mono_gc_collect(Mono.api.mono_gc_max_generation())
      const names = animals.map((a) => cls('Animal').property('Name')?.getter?.invoke(a))
      // Many temporary strings in one call: earlier arguments must stay valid while later ones allocate.
      const long = 'x'.repeat(100_000)
      const concat = (method('Calls', 'Concat').invoke(null, long, long) as string).length
      for (const a of animals) a.dispose()
      return {
        allNamed: names.every((n, i) => n === `a${i}`),
        concat
      }
    })
  },

  handles() {
    return Mono.performNow(() => {
      const before = Mono.stats.handles
      const objects = Array.from({ length: 50 }, () => raw<ManagedObject>(method('Calls', 'MakeAnimal').invoke(null, 'x')))
      const during = Mono.stats.handles
      for (const o of objects) o.dispose()
      return { grew: during - before, after: Mono.stats.handles - before }
    })
  }
}
