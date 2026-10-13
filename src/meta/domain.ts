import { scoped } from '../memory/scope'
import { readUtf8 } from '../memory/strings'
import type { MonoDomainPtr } from '../native/api.generated'
import { api } from '../native/api'
import { MonoError } from '../errors'
import { Assembly } from './assembly'
import { interner } from './intern'

/** A `MonoDomain*` (application domain). Unity and most embedders only use the root domain. */
export class Domain {
  static readonly from = interner((handle: MonoDomainPtr) => new Domain(handle))

  private constructor(readonly handle: MonoDomainPtr) {}

  static get root(): Domain {
    return Domain.from(api.mono_get_root_domain())
  }

  /** The calling thread's current domain. */
  static get current(): Domain {
    return Domain.from(api.mono_domain_get())
  }

  get id(): number {
    return api.mono_domain_get_id(this.handle)
  }

  get name(): string | null {
    return readUtf8(api.mono_domain_get_friendly_name(this.handle))
  }

  /** Loads an assembly from a file path into this domain (or returns it if already loaded). */
  open(path: string): Assembly {
    const assembly = scoped((scope) => api.mono_domain_assembly_open(this.handle, scope.utf8(path)))
    if (assembly.isNull()) throw new MonoError(`Could not load assembly from ${path}`)
    return Assembly.from(assembly)
  }

  toString(): string {
    return this.name ?? `domain ${this.id}`
  }
}
