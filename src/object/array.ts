import { Class } from '../meta/class'
import type { MonoArrayPtr, MonoObjectPtr } from '../native/api.generated'
import { api } from '../native/api'
import { scoped } from '../memory/scope'
import { marshallerFor, type Marshaller } from '../marshal/marshaller'
import { ManagedObject } from './object'

/** A managed array (`T[]`). Elements are converted on access. */
export class MArray<T = unknown> extends ManagedObject {
  #element?: Marshaller
  #elementSize?: number

  /** New array of `elementClass` holding `values`. */
  static from<T = unknown>(elementClass: Class, values: readonly unknown[]): MArray<T> {
    const array = new MArray<T>(api.mono_array_new(api.mono_domain_get(), elementClass.handle, values.length))
    values.forEach((v, i) => array.set(i, v as T))
    return array
  }

  get length(): number {
    return Number(api.mono_array_length(this.pointer as unknown as MonoArrayPtr))
  }

  get elementClass(): Class {
    return this.class.elementClass
  }

  get(index: number): T {
    return this.#marshaller.read(this.#address(index)) as T
  }

  set(index: number, value: T): void {
    const m = this.#marshaller
    scoped((scope) => {
      if (m.isReference) {
        const object = m.toStorage(value, scope)
        api.mono_gc_wbarrier_set_arrayref(this.pointer as unknown as MonoArrayPtr, this.#address(index), object as MonoObjectPtr)
      } else {
        // mono_value_copy is barrier + copy everywhere; Mono 2.6's mono_gc_wbarrier_value_copy only does the barrier.
        api.mono_value_copy(this.#address(index), m.toStorage(value, scope), this.elementClass.handle)
      }
    })
  }

  toArray(): T[] {
    return Array.from({ length: this.length }, (_, i) => this.get(i))
  }

  *[Symbol.iterator](): IterableIterator<T> {
    const length = this.length
    for (let i = 0; i < length; i++) yield this.get(i)
  }

  override toString(): string {
    return `${this.class.fullName}[${this.length}]`
  }

  get #marshaller(): Marshaller {
    return (this.#element ??= marshallerFor(this.elementClass.type))
  }

  #address(index: number): NativePointer {
    const length = this.length
    if (!Number.isInteger(index) || index < 0 || index >= length) throw new RangeError(`Index ${index} out of range for ${this.class.fullName} of length ${length}`)
    this.#elementSize ??= api.mono_array_element_size(api.mono_object_get_class(this.pointer))
    return api.mono_array_addr_with_size(this.pointer as unknown as MonoArrayPtr, this.#elementSize, index)
  }
}
