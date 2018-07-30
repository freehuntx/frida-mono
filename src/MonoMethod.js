import { MonoApiHelper } from 'frida-mono-api'
import MonoMethodSignature from './MonoMethodSignature'
import MonoObject from './MonoObject'

const mono_method_cache = {}
export default class MonoMethod {
  static from(mono_method, instance = NULL) {
    const cacheId = mono_method.toInt32()

    if (mono_method_cache[cacheId] === undefined) {
      mono_method_cache[cacheId] = MonoMethod.generateMethod(mono_method, instance)
    }

    return mono_method_cache[cacheId]
  }

  static generateMethod(mono_method, instance) {
    function generated(...args) {
      return MonoMethod.invoke(mono_method, this.$instance || instance, ...args)
    }

    let address
    Object.defineProperty(generated, 'address', {
      get: () => {
        if (address === undefined) address = MonoApiHelper.CompileMethod(mono_method)
        return address
      }
    })

    return generated
  }

  static invoke(mono_method, instance = NULL, ...args) {
    const signature = MonoMethodSignature.fromMethod(mono_method)
    const argsPtr = signature.create(...args)
    const mono_object = MonoApiHelper.RuntimeInvoke(mono_method, instance, argsPtr)
    if (!mono_object.isNull()) return MonoObject.from(mono_object).unbox()
  }
}
