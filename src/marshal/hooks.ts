import { ManagedObject } from '../object/object'
import type { StructView } from '../object/struct'

/**
 * Lets the bridge (Phase 4) present marshalled objects as instances of generated JS classes, and
 * accept those instances back as arguments, without the marshal layer depending on the bridge.
 */
export interface WrapHooks {
  /** Called for every object/struct the marshal layer returns. */
  wrapObject(object: ManagedObject): unknown
  wrapStruct(view: StructView): unknown
  /** Returns the underlying object for a bridge value (instance, struct, class-as-`System.Type`), or `undefined`. */
  unwrap(value: unknown): ManagedObject | StructView | undefined
}

const identity: WrapHooks = {
  wrapObject: (object) => object,
  wrapStruct: (view) => view,
  unwrap: () => undefined
}

export let hooks: WrapHooks = identity

/** The raw `ManagedObject` behind a value the marshal layer returned (bridge instance or not). */
export function asManagedObject(value: unknown): ManagedObject {
  const unwrapped = hooks.unwrap(value) ?? value
  if (unwrapped instanceof ManagedObject) return unwrapped
  throw new TypeError('Expected a managed object')
}

export function setWrapHooks(next: WrapHooks): void {
  hooks = next
}
