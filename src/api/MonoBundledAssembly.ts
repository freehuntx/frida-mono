import { MonoBase } from './MonoBase'

export class MonoBundledAssembly extends MonoBase {
  constructor(name = '', data: ArrayBuffer = null) {
    super()
    this.$address = Memory.alloc(Process.pointerSize + Process.pointerSize + 4)
    this.name = name
    this.data = data
  }

  set name(name: string) {
    this.$address.writePointer(Memory.allocUtf8String(name))
  }

  get name(): string {
    const address = this.$address.readPointer()
    if (address.isNull()) return null
    return address.readUtf8String()
  }

  set data(data: ArrayBuffer) {
    if (data === null) {
      this.size = 0
      this.$address.add(Process.pointerSize).writePointer(NULL)
    } else {
      this.size = data.byteLength
      const address = Memory.alloc(data.byteLength)
      address.writeByteArray(data)
      this.$address.add(Process.pointerSize).writePointer(address)
    }
  }

  get data(): ArrayBuffer {
    const dataAddress = this.$address.add(Process.pointerSize).readPointer()
    if (dataAddress.isNull()) return null
    return dataAddress.readByteArray(this.size)
  }

  set size(size: number) {
    this.$address.add(Process.pointerSize * 2).writeU32(size)
  }

  get size(): number {
    return this.$address.add(Process.pointerSize * 2).readU32()
  }
}
