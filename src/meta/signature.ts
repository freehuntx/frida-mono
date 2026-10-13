import type { MonoMethodSignaturePtr, MonoTypePtr } from '../native/api.generated'
import { api } from '../native/api'
import { interner, iterate } from './intern'
import { Type } from './type'

/** A `MonoMethodSignature*`: return type and parameter types of a method. */
export class Signature {
  static readonly from = interner((handle: MonoMethodSignaturePtr) => new Signature(handle))

  #params?: readonly Type[]

  private constructor(readonly handle: MonoMethodSignaturePtr) {}

  get returnType(): Type {
    return Type.from(api.mono_signature_get_return_type(this.handle))
  }

  get parameterTypes(): readonly Type[] {
    return (this.#params ??= Object.freeze(iterate((iter) => api.mono_signature_get_params(this.handle, iter) as MonoTypePtr).map((t) => Type.from(t))))
  }

  get parameterCount(): number {
    return api.mono_signature_get_param_count(this.handle)
  }

  /** True if the method takes `this`. */
  get hasThis(): boolean {
    return api.mono_signature_is_instance(this.handle) !== 0
  }

  /** True if parameter `index` is `out` (byref parameters without `out` are `ref`). */
  isOut(index: number): boolean {
    return api.mono_signature_param_is_out(this.handle, index) !== 0
  }

  toString(): string {
    return `${this.returnType.name} (${this.parameterTypes.map((t) => t.name).join(', ')})`
  }
}
