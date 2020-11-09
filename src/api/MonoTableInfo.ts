import { createNativeFunction } from '../core/native'

export const mono_table_info_get_rows = createNativeFunction('mono_table_info_get_rows', 'int', ['pointer'])

interface MonoTableInfoOptions {
  address?: NativePointer
}

const cache: { [address: number]: MonoTableInfo } = {}
export class MonoTableInfo {
  public $address: NativePointer

  constructor(options: MonoTableInfoOptions = {}) {
    if (options.address) {
      this.$address = options.address
    } else {
      throw new Error('Construction logic not implemented yet. (MonoTableInfo)')
    }
  }

  get rowSize(): number {
    return mono_table_info_get_rows(this.$address)
  }

  static fromAddress(address: NativePointer): MonoTableInfo {
    if (address.isNull()) return null
    const addressNumber = address.toInt32()

    if (cache[addressNumber] === undefined) {
      cache[addressNumber] = new MonoTableInfo({ address })
    }

    return cache[addressNumber]
  }
}
