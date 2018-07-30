import { MonoApiHelper, MonoApi } from 'frida-mono-api'
import MonoType from './MonoType'

const mono_object_cache = {}
export default class MonoObject {
  static from(mono_object) {
    const cacheId = mono_object.toInt32()

    if (mono_object_cache[cacheId] === undefined) {
      mono_object_cache[cacheId] = MonoObject.generateObject(mono_object)
    }

    return mono_object_cache[cacheId]
  }

  static generateObject(mono_object) {
    const mono_class = MonoApiHelper.ObjectGetClass(mono_object)
    const type = MonoType.fromClass(mono_class)

    return {
      unbox: () => type.read(mono_object),
      box: value => type.write(mono_object, value)
    }
  }
}
