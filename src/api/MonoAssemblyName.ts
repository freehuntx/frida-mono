import { createNativeFunction, MONO_PUBLIC_KEY_TOKEN_LENGTH } from 'core'
import { MonoAssembly } from './MonoAssembly'
import { MonoBase } from './MonoBase'

export const mono_assembly_name_new = createNativeFunction('mono_assembly_name_new', 'pointer', ['pointer'])
export const mono_assembly_invoke_search_hook = createNativeFunction('mono_assembly_invoke_search_hook', 'pointer', ['pointer'])

export class MonoAssemblyName extends MonoBase {
  constructor(name: string) {
    super()
    this.$address = mono_assembly_name_new(Memory.allocUtf8String(name))
  }

  get name(): string {
    return this.$address.readPointer().readUtf8String()
  }

  get culture(): string {
    return this.$address.add(Process.pointerSize).readPointer().readUtf8String()
  }

  get hashValue(): string {
    return this.$address
      .add(Process.pointerSize * 2)
      .readPointer()
      .readUtf8String()
  }

  get publicKey(): string {
    return this.$address
      .add(Process.pointerSize * 3)
      .readPointer()
      .readUtf8String()
  }

  get hashAlg(): number {
    return this.$address.add(Process.pointerSize * 4 + MONO_PUBLIC_KEY_TOKEN_LENGTH).readU32()
  }

  get hashLen(): number {
    return this.$address.add(Process.pointerSize * 4 + MONO_PUBLIC_KEY_TOKEN_LENGTH + 4).readU32()
  }

  get flags(): number {
    return this.$address.add(Process.pointerSize * 4 + MONO_PUBLIC_KEY_TOKEN_LENGTH + 4 + 4).readU32()
  }

  get major(): number {
    return this.$address.add(Process.pointerSize * 4 + MONO_PUBLIC_KEY_TOKEN_LENGTH + 4 + 4 + 4).readU16()
  }

  get minor(): number {
    return this.$address.add(Process.pointerSize * 4 + MONO_PUBLIC_KEY_TOKEN_LENGTH + 4 + 4 + 4 + 2).readU16()
  }

  get build(): number {
    return this.$address.add(Process.pointerSize * 4 + MONO_PUBLIC_KEY_TOKEN_LENGTH + 4 + 4 + 4 + 2 + 2).readU16()
  }

  get revision(): number {
    return this.$address.add(Process.pointerSize * 4 + MONO_PUBLIC_KEY_TOKEN_LENGTH + 4 + 4 + 4 + 2 + 2 + 2).readU16()
  }

  get arch(): number {
    return this.$address.add(Process.pointerSize * 4 + MONO_PUBLIC_KEY_TOKEN_LENGTH + 4 + 4 + 4 + 2 + 2 + 2 + 2).readU16()
  }

  /**
   * @returns {MonoAssembly}
   */
  invokeSearchHook(): MonoAssembly {
    const address = mono_assembly_invoke_search_hook(this.$address)
    return MonoAssembly.fromAddress(address)
  }

  static alloc(): MonoAssemblyName {
    let size = Process.pointerSize // name ptr
    size += Process.pointerSize // culture ptr
    size += Process.pointerSize // hashValue ptr
    size += Process.pointerSize // pubKey ptr
    size += MONO_PUBLIC_KEY_TOKEN_LENGTH // pubKeyToken
    size += 4 // hashAlg
    size += 4 // hashLen
    size += 4 // flags
    size += 2 // major
    size += 2 // minor
    size += 2 // build
    size += 2 // revision
    size += 2 // arch
    const address = Memory.alloc(size)
    return MonoAssemblyName.fromAddress(address)
  }
}
