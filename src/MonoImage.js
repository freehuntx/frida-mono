import { MonoApiHelper } from 'frida-mono-api'
import MonoClass from './MonoClass'

const mono_image_cache = {}
export default class MonoImage {
  static from(mono_image) {
    const cacheId = mono_image.toInt32()

    if (mono_image_cache[cacheId] === undefined) {
      mono_image_cache[cacheId] = MonoImage.generate(mono_image)
    }

    return mono_image_cache[cacheId]
  }

  static fromName(name) {
    const mono_image = MonoApiHelper.ImageLoaded(name)
    if (!mono_image.isNull()) return MonoImage.from(mono_image)
  }

  static generate(mono_image) {
    const classCache = {}
    let generated = {
      getClass: name => {
        if (classCache[name] === undefined) {
          classCache[name] = MonoClass.from(MonoApiHelper.ClassFromName(mono_image, name))
        }

        return classCache[name]
      }
    }

    return generated
  }
}
