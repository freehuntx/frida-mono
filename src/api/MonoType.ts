
interface MonoTypeOptions {
  address?: NativePointer
}

const cache: { [address: number]: MonoType } = {}
export class MonoType {
  public $address: NativePointer

  constructor(options: MonoTypeOptions = {}) {
    if (options.address) {
      this.$address = options.address
    }
    else {
      throw new Error('Construction logic not implemented yet. (MonoType)')
    }
  }

  static fromAddress(address: NativePointer): MonoType {
    if (address.isNull()) return null
    const addressNumber = address.toInt32()

    if (cache[addressNumber] === undefined) {
      cache[addressNumber] = new MonoType({ address })
    }

    return cache[addressNumber]
  }
}
