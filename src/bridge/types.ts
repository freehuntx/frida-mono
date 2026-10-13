/* eslint-disable @typescript-eslint/no-explicit-any -- these types describe a dynamic bridge */
import type { Class } from '../meta/class'
import type { Method } from '../meta/method'
import type { GcHandle } from '../object/handles'
import { internalOf } from './symbols'

/**
 * Typed surface of the bridge, used by typings that `Mono.dump({ format: 'dts' })` generates.
 * Without generated typings everything stays `any`.
 */

/** Namespaces of generated typings (augmented by them): `Mono.namespaces.Game.Player`. */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type -- augmented by generated typings
export interface MonoNamespaces {}

/** Full names → classes of generated typings (augmented by them): `Mono.use('Game.Player')`. */
// eslint-disable-next-line @typescript-eslint/no-empty-object-type -- augmented by generated typings
export interface MonoTypes {}

/** Any generated class (the static side), constructible or not (static classes have no public constructor). */
export interface MonoClassLike {
  readonly prototype: unknown
  readonly $class: Class
}

/**
 * Base of every generated class: the `$` helpers of instances and classes.
 * At runtime it's only used for `instanceof`, which is true for any bridge instance.
 */
// The class gives `instanceof`; the interface below adds the instance helpers (declaration merging).
// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export abstract class MonoObject {
  declare static readonly $class: Class
  declare static readonly $type: MonoObject
  declare static readonly $methods: unknown[]
  declare static readonly $fields: unknown[]
  declare static readonly $properties: unknown[]
  declare static readonly $events: unknown[]
  declare static readonly $nested: MonoClassLike[]
  declare static readonly $generic: boolean
  declare static readonly $of: (...types: MonoClassLike[]) => any
  declare static readonly $wrap: (pointer: NativePointer) => any
  declare static readonly $field: (name: string) => any
  declare static readonly $setField: (name: string, value: unknown) => void

  declare readonly $class: Class
  declare readonly $handle: GcHandle
  declare readonly $pointer: NativePointer
  /** Struct fields as a plain object (structs only). */
  declare readonly $value: Record<string, unknown>

  static [Symbol.hasInstance](value: unknown): boolean {
    return internalOf(value) !== undefined
  }
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export interface MonoObject {
  $cast<T extends MonoClassLike>(type: T): T['prototype']
  $is(type: MonoClassLike): boolean
  $equals(other: unknown): boolean
  $dispose(): void
  $field(name: string): any
  $setField(name: string, value: unknown): void
  $item(...index: unknown[]): any
  $setItem(...indexAndValue: unknown[]): void
}

/** `$` helpers of method functions. */
export interface MonoMethodHelpers<F> {
  readonly $overloads: string[]
  readonly $method: Method | undefined
  $overload(...types: (string | MonoClassLike)[]): MonoMethod<(...args: any[]) => any>
  $of(...types: MonoClassLike[]): MonoMethod<(...args: any[]) => any>
  $override(fn: (this: any, ...args: any[]) => unknown): MonoMethod<F>
  $attach(callbacks: { onEnter?(self: any, args: any[]): void; onLeave?(self: any, result: any): unknown }): MonoMethod<F>
  $revert(): MonoMethod<F>
  $original: F
}

/** A managed method (all overloads under one name): callable, plus `$` helpers. */
export type MonoMethod<F> = F & MonoMethodHelpers<F>

/** A managed event: subscribe with existing managed delegates. */
export interface MonoEvent {
  add(handler: unknown): void
  remove(handler: unknown): void
}
