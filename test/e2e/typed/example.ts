// Typechecked against typings that Mono.dump() generated for test/fixtures/TestLib.cs (test/e2e/dump.e2e.ts).
import Mono, { MArray, MonoObject } from 'frida-mono'

const T = Mono.namespaces.FridaMono.Tests

const dog = new T.Dog('Rex')
const speech: string = dog.Speak()
const legs: number = dog.Legs
dog.Name = 'Max'
const greeting: string = dog.Greet('you')
const isAnimal: boolean = dog instanceof T.Animal && dog instanceof MonoObject
const created: InstanceType<typeof T.Animal> = T.Dog.Create('Pup') // inherited static

const picked: string = T.Overloads.Pick(1)
const pickedString: string = T.Overloads.Pick('x')
const forced: string = T.Overloads.Pick.$overload('double')(1)

const point = new T.Point(1, 2)
const lengthSquared: number = point.LengthSquared
const sum = T.Calls.AddPoints(point, { X: 1 })
const x: number = sum.X

const blue = T.Color.Blue
const next = T.Calls.NextColor('Red')
const combined = T.Calls.Combine(T.Access.Read, 'Write')

const max: bigint = T.Calls.MaxLong()
const negated: bigint = T.Calls.NegI8(5)
const range: MArray<number> = T.Calls.Range(3)
const total: number = T.Calls.SumArray([1, 2, 3])
const maybe: number | null = T.Calls.MaybeDouble(null)

const out = Mono.ref<number>()
const ok: boolean = T.Overloads.TryDouble(2, out)

const box = new T.Box<number>(5)
const boxed: number = box.Get()
const echoed: string = T.Generics.Echo<string>('s')

const collar = new T.Dog.Collar()
collar.Tag = 'blue'

const DogByName = Mono.use('FridaMono.Tests.Dog')
const fido = new DogByName('Fido')

T.HookTargets.Twice.$override((value: number) => value * 2)
dog.Speak.$attach({ onLeave: (_self, result) => result })
T.Calls.TypeName(T.Dog)
dog.Renamed.add(null)

// @ts-expect-error: no Pick(bool)
T.Overloads.Pick(true)
// @ts-expect-error: no such member
dog.Nope()
// @ts-expect-error: Legs is readonly
dog.Legs = 3
// @ts-expect-error: abstract class
new T.Shape()

export const used = [
  speech,
  legs,
  greeting,
  isAnimal,
  created,
  picked,
  pickedString,
  forced,
  lengthSquared,
  x,
  blue,
  next,
  combined,
  max,
  negated,
  range,
  total,
  maybe,
  ok,
  boxed,
  echoed,
  fido
]
