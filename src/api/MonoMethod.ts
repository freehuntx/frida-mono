interface MonoMethodOptions {
  address?: NativePointer
}

const cache: { [address: number]: MonoMethod } = {}
export class MonoMethod {
  public $address: NativePointer

  constructor(options: MonoMethodOptions = {}) {
    if (options.address) {
      this.$address = options.address
    } else {
      throw new Error('Construction logic not implemented yet. (MonoMethod)')
    }
  }

  static fromAddress(address: NativePointer): MonoMethod {
    if (address.isNull()) return null
    const addressNumber = address.toInt32()

    if (cache[addressNumber] === undefined) {
      cache[addressNumber] = new MonoMethod({ address })
    }

    return cache[addressNumber]
  }
}
