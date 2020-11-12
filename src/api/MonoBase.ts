export class MonoBase {
  private static cache: { [address: number]: MonoBase } = {}
  public $address: NativePointer = NULL

  public static fromAddress<T>(address: NativePointer): T {
    if (address.isNull()) return null
    const addressNumber = address.toInt32()

    if (this.cache[addressNumber] === undefined) {
      const obj: MonoBase = Object.create(this.prototype)
      obj.$address = address
      this.cache[addressNumber] = obj
    }

    return (this.cache[addressNumber] as undefined) as T
  }
}
