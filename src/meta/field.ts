import { readUtf8 } from '../memory/strings'
import type { MonoClassFieldPtr } from '../native/api.generated'
import { api } from '../native/api'
import { getField, setField, type Instance } from '../invoke/invoke'
import { Class } from './class'
import { accessOf, FieldAttributes, type Access } from './constants'
import { interner } from './intern'
import { Type } from './type'

/** A `MonoClassField*`. */
export class Field {
  static readonly from = interner((handle: MonoClassFieldPtr) => new Field(handle))

  #name?: string
  #flags?: number

  private constructor(readonly handle: MonoClassFieldPtr) {}

  get name(): string {
    return (this.#name ??= readUtf8(api.mono_field_get_name(this.handle)) ?? '')
  }

  get type(): Type {
    return Type.from(api.mono_field_get_type(this.handle))
  }

  /** The declaring class. */
  get class(): Class {
    return Class.from(api.mono_field_get_parent(this.handle))
  }

  /** `FieldAttributes` flags. */
  get flags(): number {
    return (this.#flags ??= api.mono_field_get_flags(this.handle))
  }

  get access(): Access {
    return accessOf(this.flags)
  }

  get isStatic(): boolean {
    return (this.flags & FieldAttributes.STATIC) !== 0
  }

  /** `const`: the value lives only in metadata, there's no storage. */
  get isLiteral(): boolean {
    return (this.flags & FieldAttributes.LITERAL) !== 0
  }

  /** `readonly`. */
  get isInitOnly(): boolean {
    return (this.flags & FieldAttributes.INIT_ONLY) !== 0
  }

  /** Byte offset inside the object (including the object header) or, for static fields, inside the static data. */
  get offset(): number {
    return api.mono_field_get_offset(this.handle)
  }

  /** Reads the value; `instance` is ignored for static fields. */
  getValue(instance: Instance | null = null): unknown {
    return getField(this, instance)
  }

  /** Writes the value; `instance` is ignored for static fields. */
  setValue(value: unknown, instance: Instance | null = null): void {
    setField(this, instance, value)
  }

  toString(): string {
    return `${this.type.name} ${this.class.fullName}::${this.name}`
  }

  toJSON(): FieldDescriptor {
    return { name: this.name, type: this.type.name, static: this.isStatic, access: this.access, literal: this.isLiteral, readonly: this.isInitOnly }
  }
}

export interface FieldDescriptor {
  name: string
  type: string
  static: boolean
  access: Access
  literal: boolean
  readonly: boolean
}
