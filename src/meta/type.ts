import { takeUtf8 } from '../memory/strings'
import type { MonoTypePtr } from '../native/api.generated'
import { api } from '../native/api'
import { Class } from './class'
import { TypeEnum, typeEnumName } from './constants'
import { interner } from './intern'

/** A `MonoType*`: the type of a field, parameter or return value (may be byref, generic, an array, …). */
export class Type {
  static readonly from = interner((handle: MonoTypePtr) => new Type(handle))

  #name?: string
  #class?: Class

  private constructor(readonly handle: MonoTypePtr) {}

  /** The `MonoTypeEnum` (`TypeEnum.I4`, `TypeEnum.CLASS`, …). */
  get typeEnum(): TypeEnum {
    return api.mono_type_get_type(this.handle) as TypeEnum
  }

  /** IL-style name: `System.Int32`, `System.Int32&`, `System.Collections.Generic.List\`1<System.String>`, `Ns.Outer/Inner`. */
  get name(): string {
    return (this.#name ??= takeUtf8(api.mono_type_get_name(this.handle)) ?? '')
  }

  /** The class for this type; for primitives the boxed class (`System.Int32`), for `T` a generic-parameter class. */
  get class(): Class {
    return (this.#class ??= Class.from(api.mono_class_from_mono_type(this.handle)))
  }

  get isByRef(): boolean {
    return api.mono_type_is_byref(this.handle) !== 0
  }

  get isVoid(): boolean {
    return this.typeEnum === TypeEnum.VOID
  }

  /** True for reference types (classes, interfaces, strings, arrays, `object`). */
  get isReference(): boolean {
    return api.mono_type_is_reference(this.handle) !== 0
  }

  /** True for `T` / `M` generic parameters. */
  get isGenericParameter(): boolean {
    const t = this.typeEnum
    return t === TypeEnum.VAR || t === TypeEnum.MVAR
  }

  /** For enums, the underlying integer type; otherwise the type itself. */
  get underlying(): Type {
    return Type.from(api.mono_type_get_underlying_type(this.handle))
  }

  toString(): string {
    return this.name
  }

  toJSON(): { name: string; typeEnum: string; byRef: boolean } {
    return { name: this.name, typeEnum: typeEnumName(this.typeEnum), byRef: this.isByRef }
  }
}
