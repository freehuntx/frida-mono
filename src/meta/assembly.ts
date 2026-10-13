import { readUtf8, takeUtf8 } from '../memory/strings'
import type { MonoAssemblyPtr } from '../native/api.generated'
import { api } from '../native/api'
import { Image } from './image'
import { invoke } from '../invoke/invoke'
import { ManagedObject } from '../object/object'
import { interner } from './intern'

/** A `MonoAssembly*`. */
export class Assembly {
  static readonly from = interner((handle: MonoAssemblyPtr) => new Assembly(handle))

  #name?: string

  private constructor(readonly handle: MonoAssemblyPtr) {}

  /** Simple name, e.g. `Assembly-CSharp` (read via the image, which works on every runtime). */
  get name(): string {
    return (this.#name ??= readUtf8(api.mono_image_get_name(api.mono_assembly_get_image(this.handle))) ?? '')
  }

  /** Display name: `mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089`. */
  get fullName(): string {
    if (api.has('mono_assembly_get_name') && api.has('mono_stringify_assembly_name')) {
      return takeUtf8(api.mono_stringify_assembly_name(api.mono_assembly_get_name(this.handle))) ?? this.name
    }
    // Legacy runtimes: ask managed reflection (System.Reflection.Assembly.FullName).
    const reflection = new ManagedObject(api.mono_assembly_get_object(api.mono_domain_get(), this.handle))
    const getter = reflection.class.property('FullName')?.getter
    return getter === null || getter === undefined ? this.name : String(invoke(getter, reflection, []))
  }

  get image(): Image {
    return Image.from(api.mono_assembly_get_image(this.handle))
  }

  toString(): string {
    return this.name
  }

  toJSON(): { name: string; fullName: string } {
    return { name: this.name, fullName: this.fullName }
  }
}
