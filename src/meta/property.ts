import { readUtf8 } from '../memory/strings'
import type { MonoPropertyPtr } from '../native/api.generated'
import { api } from '../native/api'
import { Class } from './class'
import { interner } from './intern'
import { Method } from './method'
import type { Type } from './type'

/** A `MonoProperty*`. Indexers (`this[int]`) are properties named `Item` with parameters. */
export class Property {
  static readonly from = interner((handle: MonoPropertyPtr) => new Property(handle))

  #name?: string

  private constructor(readonly handle: MonoPropertyPtr) {}

  get name(): string {
    return (this.#name ??= readUtf8(api.mono_property_get_name(this.handle)) ?? '')
  }

  /** The declaring class. */
  get class(): Class {
    return Class.from(api.mono_property_get_parent(this.handle))
  }

  get getter(): Method | null {
    return Method.from.orNull(api.mono_property_get_get_method(this.handle))
  }

  get setter(): Method | null {
    return Method.from.orNull(api.mono_property_get_set_method(this.handle))
  }

  /** The property type: the getter's return type, or the setter's last parameter. */
  get type(): Type {
    const getter = this.getter
    if (getter !== null) return getter.returnType
    const params = this.accessor.parameters
    return (params[params.length - 1] as (typeof params)[number]).type
  }

  /** Index parameters (empty unless this is an indexer). */
  get indexParameters(): readonly Type[] {
    const getter = this.getter
    if (getter !== null) return getter.parameters.map((p) => p.type)
    return this.accessor.parameters.slice(0, -1).map((p) => p.type)
  }

  get isStatic(): boolean {
    return this.accessor.isStatic
  }

  get flags(): number {
    return api.mono_property_get_flags(this.handle)
  }

  /** The getter, or the setter for write-only properties. */
  private get accessor(): Method {
    const method = this.getter ?? this.setter
    if (method === null) throw new Error(`Property ${this.name} has no accessors`)
    return method
  }

  toString(): string {
    return `${this.type.name} ${this.class.fullName}::${this.name}`
  }

  toJSON(): PropertyDescriptor {
    return {
      name: this.name,
      type: this.type.name,
      static: this.isStatic,
      get: this.getter !== null,
      set: this.setter !== null,
      index: this.indexParameters.map((t) => t.name)
    }
  }
}

export interface PropertyDescriptor {
  name: string
  type: string
  static: boolean
  get: boolean
  set: boolean
  index: string[]
}
