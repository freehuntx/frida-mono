import { createNativeFunction, MonoImageOpenStatus } from 'core'
import { MonoBase } from './MonoBase'

export const mono_assembly_name_new = createNativeFunction('mono_assembly_name_new', 'pointer', ['pointer'])
export const mono_assembly_close = createNativeFunction('mono_assembly_close', 'void', ['pointer'])
//export const mono_assembly_get_object = createNativeFunction('mono_assembly_get_object', 'pointer', ['pointer', 'pointer'])
export const mono_assembly_load = createNativeFunction('mono_assembly_load', 'pointer', ['pointer', 'pointer', 'pointer'])
export const mono_assembly_load_full = createNativeFunction('mono_assembly_load_full', 'pointer', ['pointer', 'pointer', 'pointer', 'bool'])

export class MonoAssembly extends MonoBase {
  /**
   * This method releases a reference to the assembly. The assembly is only released when all the outstanding references to it are released.
   * @returns {void}
   */
  close(): void {
    mono_assembly_close(this.$address)
  }

  /**
   * Loads the assembly referenced by aname, if the value of basedir is not NULL, it attempts to load the assembly from that directory before probing the standard locations.
   * @param {string} name - A MonoAssemblyName with the assembly name to load.
   * @param {string} basedir - A directory to look up the assembly at.
   * @returns {MonoAssembly} The assembly referenced by name loaded.
   */
  static load(name: string, basedir: string): MonoAssembly {
    const monoAssemblyName = mono_assembly_name_new(Memory.allocUtf8String(name))
    const status = Memory.alloc(Process.pointerSize)
    const address = mono_assembly_load(monoAssemblyName, Memory.allocUtf8String(basedir), status)
    if (address.isNull()) {
      throw new Error('Failed loading MonoAssembly! Error: ' + MonoImageOpenStatus[status.readInt()])
    }
    return MonoAssembly.fromAddress(address)
  }

  /**
   * Loads the assembly referenced by aname, if the value of basedir is not NULL, it attempts to load the assembly from that directory before probing the standard locations.
   * If the assembly is being opened in reflection-only mode (refonly set to TRUE) then no assembly binding takes place.
   * @param {string} name - A MonoAssemblyName with the assembly name to load.
   * @param {string} basedir - A directory to look up the assembly at.
   * @param {boolean} refOnly - Whether this assembly is being opened in "reflection-only" mode.
   * @returns {MonoAssembly} The assembly referenced by aname loaded.
   */
  static loadFull(name: string, basedir: string, refOnly: boolean): MonoAssembly {
    const monoAssemblyName = mono_assembly_name_new(Memory.allocUtf8String(name))
    const status = Memory.alloc(Process.pointerSize)
    const address = mono_assembly_load_full(monoAssemblyName, Memory.allocUtf8String(basedir), status, refOnly)
    if (address.isNull()) {
      throw new Error('Failed loading MonoAssembly! Error: ' + MonoImageOpenStatus[status.readInt()])
    }
    return MonoAssembly.fromAddress(address)
  }
}
