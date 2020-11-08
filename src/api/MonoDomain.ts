interface MonoDomainOptions {
  address?: NativePointer
}

const cache: { [address: number]: MonoDomain } = {}
export class MonoDomain {
  public $address: NativePointer

  constructor(options: MonoDomainOptions = {}) {
    if (options.address) {
      this.$address = options.address
    } else {
      throw new Error('Construction logic not implemented yet. (MonoDomain)')
    }
  }

  static fromAddress(address: NativePointer): MonoDomain {
    if (address.isNull()) return null
    const addressNumber = address.toInt32()

    if (cache[addressNumber] === undefined) {
      cache[addressNumber] = new MonoDomain({ address })
    }

    return cache[addressNumber]
  }
}
