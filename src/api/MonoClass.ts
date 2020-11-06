import { MonoImage } from './MonoImage'
import { createNativeFunction } from '../core/native'

export const mono_class_get_fields = createNativeFunction('mono_class_get_fields', 'pointer', ['pointer', 'pointer'])
export const mono_class_from_name = createNativeFunction('mono_class_from_name', 'pointer', ['pointer', 'pointer', 'pointer'])

/**
 * Mono doc: http://docs.go-mono.com/?link=xhtml%3adeploy%2fmono-api-class.html
 */
const cache: { [address: number]: MonoClass } = {}

interface MonoClassOptions {
  address?: NativePointer
}

export class MonoClass {
  public $address: NativePointer

  constructor(options: MonoClassOptions = {}) {
    if (options.address) {
      this.$address = options.address
    }
    else {
      throw new Error('Construction logic not implemented yet. (MonoClass)')
    }
  }

  /*// See: docs.go-mono.com/monodoc.ashx?link=xhtml%3adeploy%2fmono-api-image.html#api:mono_image_get_filename
  get fileName(): string {
    return natives.mono_image_get_filename(this.$address).readUtf8String()
  }

  // See: docs.go-mono.com/monodoc.ashx?link=xhtml%3adeploy%2fmono-api-image.html#api:mono_image_get_name
  get name(): string {
    return natives.mono_image_get_name(this.$address).readUtf8String()
  }*/

  getFields() {
    const fields = []
    const iter = Memory.alloc(Process.pointerSize)
    let field

    while(!(field = mono_class_get_fields(this.$address, iter)).isNull()) {
      fields.push(field)
    }

    return fields
  }

  /**
   * Static methods
   */
  // See: docs.go-mono.com/monodoc.ashx?link=xhtml%3adeploy%2fmono-api-class.html#api:mono_class_from_name
  static fromName(image: MonoImage, namespace: string, className: string) {
    const address = mono_class_from_name(image.$address, Memory.allocUtf8String(namespace), Memory.allocUtf8String(className))
    return MonoClass.fromAddress(address)
  }

  static fromAddress(address: NativePointer) {
    if (address.isNull()) return null
    const addressNumber = address.toInt32()

    if (cache[addressNumber] === undefined) {
      cache[addressNumber] = new MonoClass({ address })
    }

    return cache[addressNumber]
  }


  // See: docs.go-mono.com/monodoc.ashx?link=xhtml%3adeploy%2fmono-api-image.html#api:mono_image_loaded
  /*static loaded(assemblyName: string): MonoImage {
    const address: NativePointer = natives.mono_image_loaded(Memory.allocUtf8String(assemblyName))
    return MonoImage.from(address)
  }

  static from(address: NativePointer) {
    if (address.isNull()) return null

    const addressNumber = address.toInt32()

    if (cache[addressNumber] === undefined) {
      cache[addressNumber] = new MonoImage({ address })
    }

    return cache[addressNumber]
  }*/
}
