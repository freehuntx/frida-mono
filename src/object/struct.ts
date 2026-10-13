import { MonoError } from '../errors'
import { scoped } from '../memory/scope'
import type { Class } from '../meta/class'
import type { Field } from '../meta/field'
import { api } from '../native/api'
import { marshallerFor, unboxedOffset } from '../marshal/marshaller'
import { ManagedObject } from './object'

/**
 * A struct value. It lives in a managed box held by a GC handle, so references inside it are seen
 * by the GC. Reading a struct (field, return value, array element) gives a *copy*, like C#: writes
 * change this copy only. Pass the view back (`obj.Position = view`) to store it.
 */
export class StructView {
  readonly class: Class
  readonly box: ManagedObject

  private constructor(klass: Class, box: ManagedObject) {
    this.class = klass
    this.box = box
  }

  /** Copies the value at `address` (unboxed bytes of `klass`) into a new view. */
  static copyOf(klass: Class, address: NativePointer): StructView {
    return new StructView(klass, new ManagedObject(api.mono_value_box(api.mono_domain_get(), klass.handle, address)))
  }

  /** `default(T)`: all fields zero. */
  static zero(klass: Class): StructView {
    return StructView.copyOf(klass, Memory.alloc(Math.max(klass.valueSize, 1)))
  }

  /** Wraps an existing boxed struct (no copy). */
  static ofBox(box: ManagedObject): StructView {
    return new StructView(box.class, box)
  }

  /** Address of the unboxed bytes (moves with the box under SGen; don't keep it). */
  get address(): NativePointer {
    return api.mono_object_unbox(this.box.pointer)
  }

  get(name: string): unknown {
    const field = this.#field(name)
    return marshallerFor(field.type).read(this.address.add(unboxedOffset(field.offset)))
  }

  set(name: string, value: unknown): void {
    const field = this.#field(name)
    scoped((scope) => api.mono_field_set_value(this.box.pointer, field.handle, marshallerFor(field.type).toStorage(value, scope)))
  }

  /** A copy that can be changed independently. */
  clone(): StructView {
    return StructView.copyOf(this.class, this.address)
  }

  /** Instance fields as a plain object (nested structs as views). */
  toJSON(): Record<string, unknown> {
    const out: Record<string, unknown> = {}
    for (const field of this.class.fields) if (!field.isStatic) out[field.name] = this.get(field.name)
    return out
  }

  toString(): string {
    return this.box.toString()
  }

  #field(name: string): Field {
    const field = this.class.field(name)
    if (field === null || field.isStatic) throw new MonoError(`${this.class.fullName} has no instance field ${name}`)
    return field
  }
}
