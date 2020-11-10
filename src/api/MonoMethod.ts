import { MonoBase } from './MonoBase'
import { MonoClassField } from './MonoClassField'
import { createNativeFunction } from '../core/native'

export const mono_method_can_access_field = createNativeFunction('mono_method_can_access_field', 'bool', ['pointer', 'pointer'])

export class MonoMethod extends MonoBase {
  /**
   * Used to determine if a method is allowed to access the specified field.
   * @param {MonoClassField} field - The field to access
   * @returns {boolean} TRUE if the given method is allowed to access the field while following the accessibility rules of the CLI.
   */
  canAccessField(field: MonoClassField): boolean {
    return mono_method_can_access_field(this.$address, field.$address)
  }
}
