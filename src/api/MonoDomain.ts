import { createNativeFunction } from 'core/native'
import { MonoAssembly } from './MonoAssembly'
import { MonoBase } from './MonoBase'

export const mono_domain_assembly_open = createNativeFunction('mono_domain_assembly_open', 'pointer', ['pointer', 'pointer'])
export const mono_domain_create = createNativeFunction('mono_domain_create', 'pointer', [])
export const mono_domain_create_appdomain = createNativeFunction('mono_domain_create_appdomain', 'pointer', ['pointer', 'pointer'])
export const mono_domain_finalize = createNativeFunction('mono_domain_finalize', 'bool', ['pointer', 'uint32'])
export const mono_domain_foreach = createNativeFunction('mono_domain_foreach', 'void', ['pointer', 'pointer'])
export const mono_domain_free = createNativeFunction('mono_domain_free', 'void', ['pointer', 'bool'])
export const mono_domain_get_by_id = createNativeFunction('mono_domain_get_by_id', 'pointer', ['int32'])
export const mono_domain_get_friendly_name = createNativeFunction('mono_domain_get_friendly_name', 'pointer', ['pointer'])
export const mono_domain_get_id = createNativeFunction('mono_domain_get_id', 'int32', ['pointer'])
export const mono_domain_has_type_resolve = createNativeFunction('mono_domain_has_type_resolve', 'bool', ['pointer'])
export const mono_domain_is_unloading = createNativeFunction('mono_domain_is_unloading', 'bool', ['pointer'])
export const mono_domain_set_config = createNativeFunction('mono_domain_set_config', 'void', ['pointer', 'pointer', 'pointer'])
export const mono_domain_set_internal = createNativeFunction('mono_domain_set_internal', 'void', ['pointer'])
export const mono_domain_set = createNativeFunction('mono_domain_set', 'bool', ['pointer', 'bool'])
export const mono_domain_unload = createNativeFunction('mono_domain_unload', 'void', ['pointer'])
export const mono_context_init = createNativeFunction('mono_context_init', 'void', ['pointer'])

export class MonoDomain extends MonoBase {
  /**
   * @returns {number}
   */
  get id(): number {
    return mono_domain_get_id(this.$address)
  }

  /**
   * @returns {string}
   */
  get friendlyName(): string {
    return mono_domain_get_friendly_name(this.$address).readUtf8String()
  }

  /**
   * @returns {boolean} TRUE if the AppDomain.TypeResolve field has been set.
   */
  get hasTypeResolve(): boolean {
    return mono_domain_has_type_resolve(this.$address)
  }

  /**
   * @returns {boolean}
   */
  get isUnloading(): boolean {
    return mono_domain_is_unloading(this.$address)
  }

  /**
   * fixme: maybe we should integrate this with mono_assembly_open ??
   * @param {string} name file name of the assembly
   * @returns {MonoAssembly}
   */
  assemblyOpen(name: string): MonoAssembly {
    const address = mono_domain_assembly_open(this.$address, Memory.allocUtf8String(name))
    return MonoAssembly.fromAddress(address)
  }

  /**
   * Request finalization of all finalizable objects inside domain. Wait timeout msecs for the finalization to complete.
   * @param {number} timeout msecs to wait for the finalization to complete, -1 to wait indefinitely
   * @returns {boolean} TRUE if succeeded, FALSE if there was a timeout
   */
  finalize(timeout: number): boolean {
    return mono_domain_finalize(this.$address, timeout)
  }

  /**
   * This releases the resources associated with the specific domain. This is a low-level function that is invoked by the AppDomain infrastructure when necessary.
   * @param {boolean} force if true, it allows the root domain to be released (used at shutdown only).
   */
  free(force: boolean): void {
    mono_domain_free(this.$address, force)
  }

  /**
   * Returns whenever VTABLE_SLOT is inside a vtable which belongs to DOMAIN.
   * @param {boolean} vtableSlot
   * @returns {boolean}
   */
  ownsVtableSlot(vtableSlot): boolean {
    // gboolean mono_domain_owns_vtable_slot (MonoDomain *domain, gpointer vtable_slot)
    throw new Error('Not implemented')
  }

  /**
   * Used to set the system configuration for an appdomain
   * Without using this, embedded builds will get 'System.Configuration.ConfigurationErrorsException: Error Initializing the configuration system. ---> System.ArgumentException:
   * The 'ExeConfigFilename' argument cannot be null.' for some managed calls.
   * @param {string} baseDir new base directory for the appdomain
   * @param {string} configFileName path to the new configuration for the app domain
   */
  setConfig(baseDir: string, configFileName: string): void {
    mono_domain_set_config(this.$address, Memory.allocUtf8String(baseDir), Memory.allocUtf8String(configFileName))
  }

  /**
   * Sets the current domain to domain.
   */
  setInternal(): void {
    mono_domain_set_internal(this.$address)
  }

  /**
   * Set the current appdomain to domain. If force is set, set it even if it is being unloaded.
   * @param {boolean} force force setting.
   * @returns {boolean} TRUE on success; FALSE if the domain is unloaded
   */
  set(force: boolean): boolean {
    return mono_domain_set(this.$address, force)
  }

  /**
   *  This routine invokes the internal System.AppDomain.DoTypeResolve and returns the assembly that matches name.
   * If name is null, the value of ((TypeBuilder)tb).FullName is used instead
   * @param {string} name the name of the type to resolve or NULL.
   * @param {MonoObject} tybeBuilder A System.Reflection.Emit.TypeBuilder, used if name is NULL.
   * @returns {MonoReflectionAssembly} A MonoReflectionAssembly or NULL if not found
   */
  tryTypeResolve(name: string, tybeBuilder: any /*MonoObject*/): void {
    // MonoReflectionAssembly* mono_domain_try_type_resolve (MonoDomain *domain, char *name, MonoObject *tb)
    throw new Error('Not implemented')
  }

  /**
   */
  tryUnload(): void {
    // void mono_domain_try_unload (MonoDomain *domain, MonoObject **exc);
    throw new Error('Not implemented')
  }

  /**
   */
  unload(): void {
    mono_domain_unload(this.$address)
  }

  /**
   * Initializes the domain's default System.Runtime.Remoting's Context.
   */
  initContext(): void {
    mono_context_init(this.$address)
  }

  /**
   * @returns {MonoDomain[]}
   */
  static get domains(): MonoDomain[] {
    const domains: MonoDomain[] = []
    mono_domain_foreach(
      new NativeCallback(
        (address: NativePointer /*, userData: NativePointer*/) => {
          domains.push(MonoDomain.fromAddress(address))
        },
        'void',
        ['pointer', 'pointer']
      ),
      NULL
    )
    return domains
  }

  /**
   * Creates a new application domain. Usually you will want to create the Application domains provide an isolation facilty for assemblies.
   * You can load assemblies and execute code in them that will not be visible to other application domains. This is a runtime-based virtualization technology.
   * It is possible to unload domains, which unloads the assemblies and data that was allocated in that domain.
   * When a domain is created a mempool is allocated for domain-specific structures, along a dedicated code manager to hold code that is associated with the domain.
   * @returns {MonoDomain} New initialized MonoDomain, with no configuration or assemblies loaded into it.
   */
  static create(): MonoDomain {
    const address = mono_domain_create()
    return MonoDomain.fromAddress(address)
  }

  /**
   * @param {string} friendlyName The friendly name of the appdomain to create
   * @param {string} configurationFile The configuration file to initialize the appdomain with
   * @returns {MonoDomain} MonoDomain initialized with the appdomain
   */
  static createAppdomain(friendlyName: string, configurationFile: string): MonoDomain {
    const address = mono_domain_create_appdomain(Memory.allocUtf8String(friendlyName), Memory.allocUtf8String(configurationFile))
    return MonoDomain.fromAddress(address)
  }

  /**
   * Use this method to safely iterate over all the loaded application domains in the current runtime.
   * @param {(domain: MonoDomain) => void} callback
   */
  static forEach(callback: (domain: MonoDomain) => void): void {
    this.domains.forEach(callback)
  }

  /**
   * @param {number} domainId the ID
   * @returns {MonoDomain} the domain for a specific domain id.
   */
  static getById(domainId: number): MonoDomain {
    const address = mono_domain_get_by_id(domainId)
    return MonoDomain.fromAddress(address)
  }

  static fromAppDomain(): MonoDomain {
    // MonoDomain *mono_domain_from_appdomain (MonoAppDomain *appdomain);
    throw new Error('Not implemented')
  }
}

//import { createNativeFunction } from 'core/native'
//import { MonoBase } from './MonoBase'
//
//export const mono_field_get_data = createNativeFunction('mono_field_get_data', 'pointer', ['pointer'])
//export const mono_field_get_offset = createNativeFunction('mono_field_get_offset', 'uint32', ['pointer'])
//export const mono_field_full_name = createNativeFunction('mono_field_full_name', 'pointer', ['pointer'])
//
//export class MonoClassField extends MonoBase {
//  /**
//   * @returns {string} A pointer to the metadata constant value or to the field data if it has an RVA flag.
//   */
//   get data(): string {
//    const address = mono_field_get_data(this.$address)
//    return address.readUtf8String()
//  }
//  /**
//   * @returns {string} The full name for the field, made up of the namespace, type name and the field name.
//   */
//  get fullName(): string {
//    const address = mono_field_full_name(this.$address)
//    return address.readUtf8String()
//  }
//
//  /**
//   * @returns {number} The field offset.
//   */
//  get offset(): number {
//    return mono_field_get_offset(this.$address)
//  }
//}
