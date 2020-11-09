export class MonoBase {
  private static cache: { [address: number]: MonoBase } = {}
  public $address: NativePointer = NULL

  constructor(address: NativePointer) {
    this.$address = address
  }

  public static fromAddress<T>(address: NativePointer): T {
    if (address.isNull()) return null
    const addressNumber = address.toInt32()

    if (this.cache[addressNumber] === undefined) {
      this.cache[addressNumber] = new this(address)
    }

    return (this.cache[addressNumber] as undefined) as T
  }
}
