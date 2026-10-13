import { scoped } from '../memory/scope'
import { readUtf8 } from '../memory/strings'
import type { MonoImagePtr } from '../native/api.generated'
import { api } from '../native/api'
import { getCapabilities } from '../runtime/capabilities'
import { Assembly } from './assembly'
import { Class } from './class'
import { Table, Token } from './constants'
import { interner } from './intern'
import { parseClassName } from './names'

/** A `MonoImage*`: the module of an assembly, which holds its types. */
export class Image {
  static readonly from = interner((handle: MonoImagePtr) => new Image(handle))

  #name?: string
  #classes?: readonly Class[]

  private constructor(readonly handle: MonoImagePtr) {}

  /** Assembly name, e.g. `Assembly-CSharp`. */
  get name(): string {
    return (this.#name ??= readUtf8(api.mono_image_get_name(this.handle)) ?? '')
  }

  /** Path of the file it was loaded from. */
  get filename(): string | null {
    return readUtf8(api.mono_image_get_filename(this.handle))
  }

  get assembly(): Assembly {
    return Assembly.from(api.mono_image_get_assembly(this.handle))
  }

  /** Number of rows in the TypeDef table (including `<Module>`). */
  get typeCount(): number {
    if (getCapabilities().imageTableRows) return api.mono_image_get_table_rows(this.handle, Table.TYPEDEF)
    return api.mono_table_info_get_rows(api.mono_image_get_table_info(this.handle, Table.TYPEDEF))
  }

  /** Every type defined in this image, nested ones included (`<Module>` excluded). Types that fail to load are skipped. */
  get classes(): readonly Class[] {
    if (this.#classes !== undefined) return this.#classes
    const classes: Class[] = []
    const rows = this.typeCount
    // Row 1 is always <Module>.
    for (let row = 2; row <= rows; row++) {
      const klass = api.mono_class_get(this.handle, Token.TYPE_DEF | row)
      if (!klass.isNull()) classes.push(Class.from(klass))
    }
    return (this.#classes = Object.freeze(classes))
  }

  /**
   * The class named `fullName` (`Ns.Name`), or `null`. Nested classes may be written
   * `Ns.Outer+Inner` or `Ns.Outer/Inner`.
   */
  class(fullName: string): Class | null {
    const { namespace, names } = parseClassName(fullName)
    let klass = scoped((scope) => Class.from.orNull(api.mono_class_from_name(this.handle, scope.utf8(namespace), scope.utf8(names[0]))))
    for (const name of names.slice(1)) klass = klass?.nested(name) ?? null
    return klass
  }

  /** Classes whose simple name is `name`, in any namespace of this image. */
  classesNamed(name: string): Class[] {
    return this.classes.filter((c) => c.name === name)
  }

  toString(): string {
    return this.name
  }

  toJSON(): { name: string; filename: string | null } {
    return { name: this.name, filename: this.filename }
  }
}
