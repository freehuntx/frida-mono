/* eslint-disable @typescript-eslint/no-explicit-any -- the bridge is dynamic by design */
import Mono, { EnumValue } from '../../../src'

function plain(value: unknown): unknown {
  if (value === null || value === undefined) return value ?? null
  if (typeof value === 'bigint') return `${value}n`
  if (value instanceof EnumValue) return value.name
  if (Array.isArray(value)) return value.map(plain)
  if (typeof value === 'object' && value !== null && Object.getPrototypeOf(value) === Object.prototype)
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plain(v)]))
  if (typeof value === 'object' || typeof value === 'function') return String(value)
  return value
}

function check(fn: () => unknown): unknown {
  try {
    return plain(fn())
  } catch (e) {
    return { threw: (e as Error).name, message: (e as Error).message.split('\n')[0] }
  } finally {
    Mono.hooks.revertAll()
  }
}

function cases(): Record<string, () => unknown> {
  const T = Mono.namespaces.FridaMono.Tests
  const H = T.HookTargets
  return {
    staticInt: () => {
      const before = H.CallTwice(5)
      H.Twice.$override(function (this: any, x: number) {
        return this.Twice.$original(x) * 10
      })
      return [before, H.CallTwice(5), H.Twice(5)]
    },
    string: () => {
      H.Greet.$override((name: string) => `Hi ${H.Greet.$original(name.toUpperCase())}`)
      return H.CallGreet('bob')
    },
    floats: () => {
      let seen: unknown[] = []
      H.Scale.$override((value: number, factor: number) => {
        seen = [value, factor]
        return H.Scale.$original(value, factor) + 0.5
      })
      return [H.CallScale(1.5, 2), seen]
    },
    long: () => {
      H.Next.$override((x: bigint) => H.Next.$original(x) * 2n)
      return H.CallNext(1099511627776n)
    },
    bool: () => {
      H.IsPositive.$override((x: number) => !H.IsPositive.$original(x))
      return [H.CallIsPositive(5), H.CallIsPositive(-5)]
    },
    instanceAll: () => {
      const a = new H()
      H.prototype.Add.$override(function (this: any, x: number) {
        return this.Value * 100 + x
      })
      return [H.CallAdd(a, 1), a.Add(2)]
    },
    instanceOne: () => {
      const a = new H()
      const b = new H()
      a.Value = 1
      b.Value = 2
      a.Add.$override(function (this: any, x: number) {
        return -this.Add.$original(x)
      })
      return [H.CallAdd(a, 10), H.CallAdd(b, 10)]
    },
    smallStruct: () => {
      H.Move.$override((p: any, dx: number) => ({ X: p.X + dx * 100, Y: p.Y + 1 }))
      return H.CallMove(3)
    },
    floatStruct: () => {
      let seen: unknown = null
      let original: unknown = null
      H.Scale3.$override((v: any, f: number) => {
        seen = [v.$value, f]
        const r = H.Scale3.$original(v, f)
        original = r.$value
        return { X: r.X + 0.5, Y: r.Y, Z: r.Z + 100 }
      })
      return [H.CallScale3(1), seen, original]
    },
    bigStruct: () => {
      let seen: unknown = null
      H.Shift.$override((b: any, d: bigint) => {
        seen = [b.$value, d]
        const r = H.Shift.$original(b, d)
        return { A: r.A * 2n, B: r.B, C: -1n }
      })
      return [H.CallShift(3n), seen]
    },
    outParam: () => {
      H.Fill.$override((seed: number, result: any) => {
        result.value = seed * 1000
      })
      return H.CallFill(4)
    },
    managedExceptionSwallowed: () => {
      H.Check.$override((x: number) => H.Check.$original(x))
      return [H.CallCheck(5), H.CallCheck(-1)]
    },
    managedExceptionCaughtInHook: () => {
      H.Check.$override((x: number) => {
        try {
          return H.Check.$original(x)
        } catch (e) {
          return e instanceof Mono.ManagedError ? 777 : 0
        }
      })
      return H.CallCheck(-1)
    },
    jsError: () => {
      H.Twice.$override(() => {
        throw new Error('oops')
      })
      return H.CallTwice(5)
    },
    attach: () => {
      const log: unknown[] = []
      H.Twice.$attach({
        onEnter(_self: unknown, args: unknown[]) {
          log.push(['enter', args[0]])
          args[0] = (args[0] as number) + 1
        },
        onLeave(_self: unknown, result: unknown) {
          log.push(['leave', result])
          return (result as number) + 1000
        }
      })
      return [H.CallTwice(5), log]
    },
    revert: () => {
      H.Twice.$override(() => 0)
      const hooked = H.CallTwice(5)
      H.Twice.$revert()
      return [hooked, H.CallTwice(5), Mono.hooks.list().length]
    },
    overloadedNeedsChoice: () => T.Overloads.Pick.$override(() => 'x'),
    overloadChosen: () => {
      T.Overloads.Pick.$overload('int').$override(() => 'hooked int')
      return [T.Overloads.Pick(1), T.Overloads.Pick('s')]
    },
    trace: () => {
      const lines: string[] = []
      const stop = Mono.trace('FridaMono.Tests.HookTargets:Call*', (line) => lines.push(line))
      H.CallTwice(21)
      stop()
      H.CallTwice(1)
      return lines.filter((l) => l.includes('CallTwice'))
    },
    symbolicate: () => {
      const code = Mono.api.mono_compile_method(H.Twice.$method.handle)
      return [Mono.symbolicate(code.add(1)), Mono.symbolicate(ptr(8))]
    },
    assignmentRejected: () => {
      H.Twice = () => 1
    }
  }
}

rpc.exports = {
  run() {
    return Mono.performNow(() => Object.fromEntries(Object.entries(cases()).map(([name, fn]) => [name, check(fn)])))
  },

  async otherThread() {
    const T = Mono.performNow(() => Mono.namespaces.FridaMono.Tests)
    Mono.performNow(() => {
      T.Ticker.Start()
      T.Ticker.Step.$override((i: number) => i * 1000 + 7)
    })
    await new Promise((resolve) => setTimeout(resolve, 200))
    const last = Mono.performNow(() => T.Ticker.Last)
    Mono.performNow(() => Mono.hooks.revertAll())
    await new Promise((resolve) => setTimeout(resolve, 50))
    const after = Mono.performNow(() => T.Ticker.Last)
    return { last, after }
  },

  installForUnload() {
    Mono.performNow(() => Mono.namespaces.FridaMono.Tests.HookTargets.Twice.$override(() => -1))
  },

  callTwice(x: number) {
    return Mono.performNow(() => Mono.namespaces.FridaMono.Tests.HookTargets.CallTwice(x))
  }
}
