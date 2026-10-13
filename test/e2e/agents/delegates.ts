/* eslint-disable @typescript-eslint/no-explicit-any -- the bridge is dynamic by design */
import Mono from '../../../src'

function check(fn: () => unknown): unknown {
  try {
    return fn()
  } catch (e) {
    return { threw: (e as Error).name, message: (e as Error).message.split('\n')[0] }
  }
}

rpc.exports = {
  run() {
    return Mono.performNow(() => {
      const T = Mono.namespaces.FridaMono.Tests
      const D = T.Delegates
      const System = Mono.namespaces.System
      let ran = 0
      const events: string[] = []
      const dog = new T.Dog('Rex')
      const onRenamed = (sender: any, args: any) => events.push(`${sender.Name}:${String(args.$class.name)}`)
      return {
        func: check(() => D.Apply((x: number) => x * 3, 5)),
        twoArgs: check(() => D.Join((a: string, b: string) => `${a}${b}!`)),
        action: check(() => {
          D.Run(() => ran++)
          D.Run(() => ran++)
          return ran
        }),
        struct: check(() => D.MapPoint((p: any) => ({ X: p.X * 10, Y: p.Y })).$value),
        customDelegate: check(() => D.UseCombine((x: number, animal: any) => x * 2 + (animal instanceof T.Dog ? 100 : 0))),
        explicit: check(() => {
          let called = 0
          const action = Mono.delegate(System.Action, () => called++)
          ;(action as any).Invoke()
          return [called, String((action as any).$class.fullName)]
        }),
        event: check(() => {
          dog.Renamed.add(onRenamed)
          D.Raise(dog)
          dog.Renamed.remove(onRenamed) // same function → same delegate, so remove works
          D.Raise(dog)
          return events
        }),
        throws: check(() =>
          D.Apply(() => {
            throw new Error('nope')
          }, 1)
        ),
        notADelegate: check(() => T.Calls.Describe(() => 1))
      }
    })
  }
}
