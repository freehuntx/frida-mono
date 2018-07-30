import { MonoApiHelper } from 'frida-mono-api'
import { FieldAttrs } from './constants'
import MonoMethod from './MonoMethod'
import MonoObject from './MonoObject'

const mono_class_cache = {}
export default class MonoClass {
  static from(mono_class) {
    const cacheId = mono_class.toInt32()

    if (mono_class_cache[cacheId] === undefined) {
      mono_class_cache[cacheId] = MonoClass.generateClass(mono_class)
    }

    return mono_class_cache[cacheId]
  }

  static generateClass(mono_class) {
    class GeneratedClass {
      constructor(...args) {
        if (args.length === 1 && args[0] && args[0].isNull && !args[0].isNull()) {
          // TODO: Implement check for isInst to make this check perfect
          this.$instance = args[0]
        }
        else {
          this.$instance = MonoApiHelper.ObjectNew(mono_class)
          this['.ctor'](...args)
        }
      }

      static $instantiate(mono_object) {
        return new GeneratedClass(mono_object)
      }
    }

    // Build the fields
    MonoApiHelper.ClassGetFields(mono_class).forEach(mono_field => {
      const name = MonoApiHelper.FieldGetName(mono_field)
      const flags = MonoApiHelper.FieldGetFlags(mono_field)
      const isStatic = (flags & FieldAttrs.STATIC)

      Object.defineProperty(isStatic ? GeneratedClass : GeneratedClass.prototype, name, {
        enumerable: true,
        get: function() {
          const mono_object = MonoApiHelper.FieldGetValueObject(mono_field, isStatic ? NULL : this.$instance)
          if (!mono_object.isNull()) return MonoObject.from(mono_object).unbox()
        },
        set: value => { throw new Error('Setter logic not implemented') }
      })
    })

    // Build the methods
    MonoApiHelper.ClassGetMethods(mono_class).forEach(mono_method => {
      const name = MonoApiHelper.MethodGetName(mono_method)
      const flags = MonoApiHelper.MethodGetFlags(mono_method)
      const isStatic = (flags & FieldAttrs.STATIC)

      if (name.startsWith('get_')) {
        let getter
        Object.defineProperty(isStatic ? GeneratedClass : GeneratedClass.prototype, name.substr(4), {
          configurable: true,
          enumerable: true,
          get: function () {
            return MonoMethod.invoke(mono_method, isStatic ? undefined : this.$instance)
          }
        })
      }
      else if (name.startsWith('set_')) {
        Object.defineProperty(isStatic ? GeneratedClass : GeneratedClass.prototype, name.substr(4), {
          configurable: true,
          enumerable: true,
          set: function (value) {
            MonoMethod.invoke(mono_method, isStatic ? undefined : this.$instance, value)
          }
        })
      }
      else {
        if (isStatic)
          GeneratedClass.__proto__[name] = MonoMethod.from(mono_method)
        else
          GeneratedClass.prototype[name] = MonoMethod.from(mono_method)
      }
    })

    return GeneratedClass
  }
}
