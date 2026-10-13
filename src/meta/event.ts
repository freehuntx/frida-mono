import { readUtf8 } from '../memory/strings'
import type { MonoEventPtr } from '../native/api.generated'
import { api } from '../native/api'
import { Class } from './class'
import { interner } from './intern'
import { Method } from './method'
import type { Type } from './type'

/** A `MonoEvent*`. */
export class Event {
  static readonly from = interner((handle: MonoEventPtr) => new Event(handle))

  #name?: string

  private constructor(readonly handle: MonoEventPtr) {}

  get name(): string {
    return (this.#name ??= readUtf8(api.mono_event_get_name(this.handle)) ?? '')
  }

  /** The declaring class. */
  get class(): Class {
    return Class.from(api.mono_event_get_parent(this.handle))
  }

  get add(): Method | null {
    return Method.from.orNull(api.mono_event_get_add_method(this.handle))
  }

  get remove(): Method | null {
    return Method.from.orNull(api.mono_event_get_remove_method(this.handle))
  }

  get raise(): Method | null {
    return Method.from.orNull(api.mono_event_get_raise_method(this.handle))
  }

  /** The delegate type, from the `add` accessor's parameter. */
  get type(): Type | null {
    return (this.add ?? this.remove)?.parameters[0]?.type ?? null
  }

  get isStatic(): boolean {
    return (this.add ?? this.remove)?.isStatic ?? false
  }

  toString(): string {
    return `event ${this.type?.name ?? '?'} ${this.class.fullName}::${this.name}`
  }

  toJSON(): EventDescriptor {
    return { name: this.name, type: this.type?.name ?? null, static: this.isStatic }
  }
}

export interface EventDescriptor {
  name: string
  type: string | null
  static: boolean
}
