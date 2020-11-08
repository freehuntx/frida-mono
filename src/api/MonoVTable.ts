interface MonoVTableOptions {
  address?: NativePointer
}

const cache: { [address: number]: MonoVTable } = {}
export class MonoVTable {
  public $address: NativePointer

  constructor(options: MonoVTableOptions = {}) {
    if (options.address) {
      this.$address = options.address
    } else {
      throw new Error('Construction logic not implemented yet. (MonoVTable)')
    }
  }

  static fromAddress(address: NativePointer): MonoVTable {
    if (address.isNull()) return null
    const addressNumber = address.toInt32()

    if (cache[addressNumber] === undefined) {
      cache[addressNumber] = new MonoVTable({ address })
    }

    return cache[addressNumber]
  }
}
