# frida-mono

Use Mono (Unity) managed code from [Frida](https://frida.re) like plain JavaScript.

```ts
import Mono from 'frida-mono'

Mono.perform(
  () => {
    const { Game, UnityEngine } = Mono.namespaces
    const player = Game.Player.Instance // static property
    player.Health = 9999 // property setter
    player.TakeDamage.$override(function (amount: number) {
      return this.TakeDamage.$original(0) // hook, call through with a new argument
    })
    console.log(UnityEngine.Application.version)
  },
  { waitFor: 'Assembly-CSharp' }
)
```

- Classes, objects, fields, properties, methods, events, generics, structs, enums, arrays, `ref`/`out`
  and exceptions behave like JavaScript, with overload resolution picking the right method from the arguments.
- Hooks with `$override` / `$attach`, call tracing with glob patterns, backtrace symbolication.
- JS functions turn into managed delegates (`Action`, `Func<…>`, `UnityAction`, custom ones) wherever one is expected.
- A dumper that writes TypeScript typings for a game, so the bridge is fully typed in your editor.
- Works with stock Mono (4.8 – 6.12) and Unity's runtimes: `mono-2.0-bdwgc` (MonoBleedingEdge) and the legacy
  Mono 2.6 of older Unity versions. All five are tested end to end in CI.

> **Status: 2.0 alpha.** The API may still change. See [limitations](#runtime-support-and-limitations) for what is missing.

## Contents

- [Getting started](#getting-started)
- [Waiting for the runtime](#waiting-for-the-runtime)
- [Classes and objects](#classes-and-objects)
- [Values and conversions](#values-and-conversions)
- [Generics](#generics)
- [Delegates and events](#delegates-and-events)
- [Hooks](#hooks)
- [Tracing](#tracing)
- [Typings for a game](#typings-for-a-game)
- [Reflection (meta) API](#reflection-meta-api)
- [Low-level API](#low-level-api)
- [Errors](#errors)
- [Runtime support and limitations](#runtime-support-and-limitations)
- [Development](#development)

## Getting started

```sh
npm install frida-mono
```

Frida loads a single script file, so bundle your agent with any bundler (Vite, esbuild, `frida-compile`, …).
This repository has a small helper that does it with Vite:

```sh
npm run build:agent examples/game-smoke.ts -- --watch   # → .build/game-smoke.js, rebuilt on change
frida -n Game.exe -l .build/game-smoke.js                # frida reloads the script when it changes
```

## Waiting for the runtime

Everything that touches managed code must run on a thread attached to Mono. Use one of:

| Call                                    | What it does                                                                                                                                             |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Mono.perform(fn, { waitFor? })`        | Waits until Mono is loaded and initialized (and the named assemblies are loaded), attaches the thread and runs `fn`. Returns a promise of `fn`'s result. |
| `Mono.performNow(fn)`                   | Runs `fn` right away; throws `MonoNotFoundError` if Mono isn't ready.                                                                                    |
| `Mono.attachThread()`                   | Attaches the current thread (hooks and callbacks do this for you).                                                                                       |
| `Mono.onAssemblyLoad((asm, name) => …)` | Called for every assembly loaded from now on. Returns a remover.                                                                                         |

When `perform` has to wait (you spawned the game, or attached early), `fn` runs synchronously on the thread that
finished initializing Mono or loading the assembly, before game code gets to use it. That's the moment to install hooks
on startup code.

Other runtime info: `Mono.module` (the Mono `Module`), `Mono.version` (build info string, `null` on legacy runtimes),
`Mono.capabilities`, `Mono.ready`, `Mono.domain`, `Mono.assemblies`.

## Classes and objects

### Finding classes

```ts
const { System, UnityEngine, Game } = Mono.namespaces // lazy namespace tree across all assemblies
const Player = Game.Player
const Inventory = Game.Player.Inventory // nested class (Game.Player+Inventory)

Mono.use('Game.Player') // by full name
Mono.use('Assembly-CSharp', 'Game.Player') // from one assembly
Mono.use('Game.Player+Inventory') // nested
Mono.use('System.Collections.Generic.List<string>') // generic instance (C# aliases work)
```

Classes without a namespace live directly under `Mono.namespaces` (`Mono.namespaces.GameManager`).

### Using them

Bridge classes are JS classes; instances are JS objects with the managed members on them:

```ts
const player = new Game.Player('Bob', 3) // constructor overload picked from the arguments
player.Name // property getter / field read
player.Name = 'Max' // property setter / field write
player.Attack(target) // virtual call
Game.Player.Count // static field or property
Game.Player.Create('Pup') // static method, inherited statics work too

player instanceof
  Game.Player // also works for base classes and interfaces
  `${player}` // calls ToString()
```

Writing to a method, an unknown member or a read-only property throws instead of silently creating a JS property.
Member names follow C#, so they never clash with JS: library helpers all start with `$`.

| Instance helper                        | Description                                                               |
| -------------------------------------- | ------------------------------------------------------------------------- |
| `obj.$class`                           | The runtime `Class` (reflection API).                                     |
| `obj.$cast(Type)` / `obj.$is(Type)`    | View the object as another type / type check.                             |
| `obj.$equals(other)`                   | Reference equality (two wrappers of the same object).                     |
| `obj.$field(name)` / `obj.$setField()` | Any field by name, e.g. compiler-generated `<Age>k__BackingField`.        |
| `obj.$item(i)` / `obj.$setItem(i, v)`  | The indexer (`this[…]`).                                                  |
| `obj.$value`                           | Struct fields as a plain object.                                          |
| `obj.$pointer` / `obj.$handle`         | The `MonoObject*` (may move under a moving GC) and the GC handle.         |
| `obj.$dispose()`                       | Frees the GC handle now instead of when the wrapper is garbage-collected. |

| Class helper                                     | Description                                                                     |
| ------------------------------------------------ | ------------------------------------------------------------------------------- |
| `Cls.$class`                                     | The `Class`.                                                                    |
| `Cls.$type`                                      | The `System.Type` object (bridge classes also convert to `Type` automatically). |
| `Cls.$methods` `$fields` `$properties` `$events` | Reflection lists.                                                               |
| `Cls.$nested`                                    | Nested classes.                                                                 |
| `Cls.$of(...types)`                              | A generic instance (see [Generics](#generics)).                                 |
| `Cls.$wrap(pointer)`                             | Wraps a raw `MonoObject*`.                                                      |
| `Cls.$field(name)` / `Cls.$setField(name, v)`    | Any static field by name.                                                       |

### Overloads

The bridge scores every overload against the JS arguments (exact integer ranges, `float` vs `double`, subclass
distance, `null`, enums by name, …) and throws `OverloadError` listing the candidates if none or several fit equally.
Pick one explicitly with `$overload`, by parameter type names or bridge classes:

```ts
Game.Math.Clamp(5, 0, 10) // int overload
Game.Math.Clamp(0.5, 0, 1) // double/float overload
Game.Math.Clamp.$overload('float', 'float', 'float')(0.5, 0, 1)
Game.Math.Clamp.$overloads // ['Clamp(int,int,int)', 'Clamp(float,float,float)', …]
```

## Values and conversions

| Managed                             | JavaScript                                                                                          |
| ----------------------------------- | --------------------------------------------------------------------------------------------------- |
| `bool`                              | `boolean`                                                                                           |
| `sbyte` … `uint`, `float`, `double` | `number` (range-checked)                                                                            |
| `long`, `ulong`                     | `bigint` (`number` accepted as an argument)                                                         |
| `char`                              | one-character `string`                                                                              |
| `string`                            | `string`                                                                                            |
| `IntPtr`, pointers                  | `NativePointer`                                                                                     |
| enums                               | `EnumValue` (`.name`, `valueOf()`); arguments accept the value, its name (`'Read'`) or a number     |
| structs                             | struct view with fields as properties; arguments accept a view or a plain object (`{ X: 1, Y: 2 }`) |
| `T?`                                | the value or `null`                                                                                 |
| arrays                              | `MArray<T>` (indexable, iterable, `.length`, `.toArray()`); arguments accept JS arrays              |
| `System.Type`                       | arguments accept bridge classes                                                                     |
| delegates                           | arguments accept JS functions                                                                       |
| other objects                       | bridge instances                                                                                    |
| `IEnumerable`                       | instances are iterable: `for (const item of list)`, `[...dict.Keys]`                                |

```ts
const out = Mono.ref<number>() // out parameter
System.Int32.TryParse('42', out) // true; out.value === 42
const counter = Mono.ref(5) // ref parameter, read .value after the call

Mono.box(System.Single.$class, 1.5) // a boxed float, for an `object` parameter
Mono.string('text') // a System.String object, when you need the object itself
Mono.unwrap(player) // the low-level ManagedObject / StructView behind a bridge instance
```

Struct values are copies, like in C#: `transform.position.x = 1` changes a copy. Read, change and write back:

```ts
const pos = transform.position
pos.x += 1
transform.position = pos
```

## Generics

```ts
const { List, Dictionary } = System.Collections.Generic
const Names = List.$of(System.String) // or Mono.use('List<string>')
const names = new Names()
names.Add('a')
names.$item(0) // 'a'
;[...names] // ['a']

Game.Util.Echo(5) // generic method, T inferred from the arguments
Game.Util.Empty.$of(System.Int32)() // explicit type arguments
```

## Delegates and events

JS functions are converted to managed delegates wherever a delegate parameter is expected:

```ts
button.onClick.AddListener(() => console.log('clicked')) // UnityAction
list.RemoveAll((item: any) => item.IsDead) // Predicate<T>
Game.Util.Apply((x: number) => x * 3, 5) // Func<int,int>

const action = Mono.delegate(System.Action, () => …) // explicitly
```

Events have `add` / `remove`; the same function and delegate type always give the same delegate, so removing works:

```ts
const onDied = (sender: any, args: any) => console.log(`${sender.Name} died`)
player.Died.add(onDied)
player.Died.remove(onDied)
```

If a JS callback throws, the error is logged and the managed caller gets the default value.
Delegates are built with `System.Reflection.Emit`, which aggressive Unity code stripping can remove.
Delegates with `ref`/`out` parameters are not supported yet.

## Hooks

```ts
// Replace a method for every call. `this` is the instance (the class for static methods).
Game.Player.prototype.TakeDamage.$override(function (amount: number) {
  console.log(`${this.Name} takes ${amount}`)
  return this.TakeDamage.$original(amount / 2) // call the real implementation
})

// Replace it for one object only.
player.TakeDamage.$override(function (amount: number) {})

// Observe calls; onEnter can change args, onLeave can return a replacement result.
Game.Shop.Price.$attach({
  onEnter(self, args) {
    args[0] = 1
  },
  onLeave(self, result) {
    return 0
  }
})

Game.Player.prototype.TakeDamage.$revert()
Mono.hooks.list() // hooked methods
Mono.hooks.revertAll() // also happens automatically when the script unloads
```

Hooks work on all supported runtimes for primitive, string, enum, object and pointer parameters. Struct parameters and
results are supported on x64 Linux/macOS (Windows and arm64 struct calling conventions aren't modelled yet; such hooks
throw a clear error). Methods of generic types can't be hooked yet.

A managed exception can't be thrown back into the caller across a hook: if your hook throws (or doesn't catch an
exception from `$original`), the error is logged and the caller gets the default value. Catch `Mono.ManagedError`
inside the hook where that matters.

The JIT may inline small methods into their callers, so a hook on such a method won't see those calls.

## Tracing

```ts
const stop = Mono.trace('Game.*Player*:Take*') // 'Class:Method' globs; logs calls with arguments and results
stop()

Mono.findMethods('UnityEngine.Input:Get*') // Method[]
Thread.backtrace(this.context).map(Mono.symbolicate) // native addresses → managed methods
```

## Typings for a game

Without typings everything from the bridge is `any`. Generate typings from the running game and the bridge is typed:
members, overloads, generics, nested classes, enums, statics, inheritance and `$` helpers.

```sh
npx frida-mono dump -n Game.exe -o types/Game.d.ts                        # non-framework assemblies
npx frida-mono dump -n Game.exe -a Assembly-CSharp -a UnityEngine.CoreModule -o types/Game.d.ts
npx frida-mono dump -H 127.0.0.1 -n Game.exe --wait Assembly-CSharp -o types/Game.d.ts
npx frida-mono dump -p 1234 --format cs                                   # C#-like listing to stdout
```

Options: `-n NAME` / `-p PID` target, `-H HOST` remote frida-server, `-U` USB device, `-a NAME` assembly (repeatable),
`--format dts|cs|json`, `--wait NAME` wait for an assembly, `-o FILE` output. The CLI needs the `frida` npm package.

Include the file in your `tsconfig.json`; it augments `frida-mono`'s `MonoNamespaces` and `MonoTypes`:

```ts
const { Game } = Mono.namespaces // typed
const player = new Game.Player('Bob') // InstanceType<typeof Game.Player>
const p = Mono.use('Game.Player') // typed by its full name too
```

From inside an agent: `Mono.dump({ assemblies: ['Assembly-CSharp'], format: 'dts' | 'cs' | 'json' })`.

## Reflection (meta) API

The bridge is built on wrappers of Mono's metadata, available directly:

```ts
const klass = Mono.class('Game.Player') // or Mono.findClass (null if missing), Game.Player.$class
;(klass.fullName, klass.parent, klass.interfaces, klass.isValueType, klass.isEnum, klass.isInterface)
;(klass.fields, klass.methods, klass.properties, klass.events, klass.nestedClasses)
;(klass.method('TakeDamage', 1), klass.field('health'), klass.property('Name'))

const method = klass.method('TakeDamage')!
method.parameters // [{ name, type, byRef, out }]
;(method.returnType, method.isStatic, method.isVirtual, method.access)
method.invoke(instance, 5) // low-level call

const field = klass.field('health')!
;(field.type.name, field.offset, field.getValue(instance), field.setValue(100, instance))

Mono.assembly('Assembly-CSharp').image.classes // every class of an assembly
Mono.findClasses('Player') // every class with this name (or full name) across assemblies
Mono.findMethod('Game.Player:TakeDamage(int)') // Mono's method description syntax
```

## Low-level API

`Mono.api` is the Mono C API, typed from Mono's headers (810 functions) and bound lazily:

```ts
const domain = Mono.api.mono_domain_get()
Mono.api.has('mono_unity_liveness_calculation_begin') // is it exported?
```

Functions that a runtime doesn't export throw `MonoApiMissingError` when called; a few that Unity's legacy Mono lacks
(`mono_string_length`, `mono_object_to_string`, …) are replaced by equivalents. The module also exports
`ManagedObject`, `StructView`, `MArray`, `Scope`/`scoped` (native memory freed at the end of a block),
`persistentCallback` and the invoke / marshal functions the bridge uses.

`Mono.stats` has debug counters, e.g. `Mono.stats.handles`, the number of GC handles held by wrappers.

## Errors

| Error                 | When                                                                                                                |
| --------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `ManagedError`        | A managed exception: `.type` (e.g. `System.ArgumentException`), `.managedStack`, `.managed` (the exception object). |
| `OverloadError`       | No overload, or several equally good ones, fit the arguments.                                                       |
| `MonoNotFoundError`   | Mono isn't loaded, or an assembly / class wasn't found.                                                             |
| `MonoApiMissingError` | The runtime doesn't export a needed function.                                                                       |
| `MonoError`           | Base class of the above (except `ManagedError`).                                                                    |

All are available on `Mono` (`Mono.ManagedError`) and as named exports.

## Runtime support and limitations

| Runtime                                   | Tested in CI | Notes                                                                                   |
| ----------------------------------------- | ------------ | --------------------------------------------------------------------------------------- |
| Mono 6.12                                 | ✓            |                                                                                         |
| Mono 5.20                                 | ✓            |                                                                                         |
| Mono 4.8                                  | ✓            |                                                                                         |
| Unity MonoBleedingEdge (`mono-2.0-bdwgc`) | ✓            | Unity 2017.1+ with the .NET 4.x scripting runtime.                                      |
| Unity legacy Mono 2.6 (`mono.dll`)        | ✓            | Older Unity versions. Some exports are missing; see [docs/exports.md](docs/exports.md). |

IL2CPP games have no Mono runtime; use [frida-il2cpp-bridge](https://github.com/vfsfitvnm/frida-il2cpp-bridge) for those.

Not supported yet: hooks on methods of generic types, struct hooks on Windows and arm64, delegates with `ref`/`out`
parameters, optional and `params` arguments in overload resolution, and defining managed subclasses from JS.

## Development

Requires Node 24+ (npm ≥ 11.10) and Docker.

With Nix: `direnv allow` (or `nix develop`) gives you Node/npm and `frida`/`frida-ps` pinned to the same Frida version
as the npm package.

```sh
npm install
npm run typecheck && npm run lint && npm test   # unit tests (no Mono needed)
npm run build                                   # dist/ (library, typings, CLI agent)
npm run test:e2e                                # e2e against every runtime in test/e2e/runtimes.json
npm run test:e2e mono-6.12                      # a single runtime
npm run gen:api                                 # regenerate src/native/api.generated.ts from Mono's headers
node scripts/build-unity-images.mjs mbe         # build a Unity runtime image (mbe | legacy)
```

### How the e2e tests work

For each runtime, a container from that runtime's image compiles `test/fixtures/*.cs` and runs `Host.exe` (or, for
the Unity runtimes, `docker/unity-host.c`, which embeds Mono the way a Unity player does). A second container with
Node and Frida shares its PID namespace and attaches to it. This lets current Frida test runtimes whose Linux userland
is far too old to run Node (e.g. Mono 4.8 on Debian 7).

Tests load agents from `test/e2e/agents/` (bundled with Vite on the fly) and call their `rpc.exports`.
`test/e2e/typed/example.ts` is typechecked against typings generated from the fixture.

## License

MIT
