import { MonoBase } from './MonoBase'
import { createNativeFunction } from '../core/native'

export const mono_table_info_get_rows = createNativeFunction('mono_table_info_get_rows', 'int', ['pointer'])

export class MonoTableInfo extends MonoBase {
  get rowSize(): number {
    return mono_table_info_get_rows(this.$address)
  }
}
