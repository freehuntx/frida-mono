import { createNativeFunction } from '../core/native'

export const mono_image_loaded = createNativeFunction('mono_image_loaded', 'pointer', ['pointer'])
export const mono_image_get_filename = createNativeFunction('mono_image_get_filename', 'pointer', ['pointer'])
export const mono_image_get_name = createNativeFunction('mono_image_get_name', 'pointer', ['pointer'])

/**
 * Mono doc: http://docs.go-mono.com/?link=xhtml%3adeploy%2fmono-api-image.html
 */

interface MonoImageOptions {
  address?: NativePointer
}

const cache: { [address: number]: MonoImage } = {}
export class MonoImage {
  public $address: NativePointer

  constructor(options: MonoImageOptions = {}) {
    if (options.address) {
      this.$address = options.address
    }
    else {
      throw new Error('Construction logic not implemented yet. (MonoImage)')
    }
  }

  get fileName(): string {
    return mono_image_get_filename(this.$address).readUtf8String()
  }

  get name(): string {
    return mono_image_get_name(this.$address).readUtf8String()
  }

  /**
   * Static methods
   */
  static loaded(assemblyName: string): MonoImage {
    const address: NativePointer = mono_image_loaded(Memory.allocUtf8String(assemblyName))
    return MonoImage.fromAddress(address)
  }

  static fromAddress(address: NativePointer) {
    if (address.isNull()) return null

    const addressNumber = address.toInt32()

    if (cache[addressNumber] === undefined) {
      cache[addressNumber] = new MonoImage({ address })
    }

    return cache[addressNumber]
  }
}
