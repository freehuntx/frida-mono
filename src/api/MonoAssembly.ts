import { createNativeFunction } from 'core/native'
import { MonoBase } from './MonoBase'

const mono_assembly_close = createNativeFunction('mono_assembly_close', 'void', ['pointer'])

export class MonoAssembly extends MonoBase {
  /**
   * This method releases a reference to the assembly. The assembly is only released when all the outstanding references to it are released.
   * @returns {void}
   */
  close(): void {
    mono_assembly_close(this.$address)
  }
}
