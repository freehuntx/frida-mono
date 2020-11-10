import { MonoBase } from './MonoBase'
import { createNativeFunction } from '../core/native'

export const mono_field_get_data = createNativeFunction('mono_field_get_data', 'pointer', ['pointer'])

export class MonoClassField extends MonoBase {
  /**
   * @returns {string} A pointer to the metadata constant value or to the field data if it has an RVA flag.
   */
  get data(): string {
    const address = mono_field_get_data(this.$address)
    return address.readUtf8String()
  }
}
