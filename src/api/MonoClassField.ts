
interface MonoClassFieldOptions {
  address?: NativePointer
}

const cache: { [address: number]: MonoClassField } = {}
export class MonoClassField {
  public $address: NativePointer

  constructor(options: MonoClassFieldOptions = {}) {
    if (options.address) {
      this.$address = options.address
    }
    else {
      throw new Error('Construction logic not implemented yet. (MonoClassField)')
    }
  }

  static fromAddress(address: NativePointer): MonoClassField {
    if (address.isNull()) return null
    const addressNumber = address.toInt32()

    if (cache[addressNumber] === undefined) {
      cache[addressNumber] = new MonoClassField({ address })
    }

    return cache[addressNumber]
  }
}
