import { MonoApiHelper } from 'frida-mono-api'
import MonoType from './MonoType'

const mono_method_cache = {}
export default class MonoMethodSignature {
  static fromMethod(mono_method) {
    const cacheId = mono_method.toInt32()

    if (mono_method_cache[cacheId] === undefined) {
      const mono_signature = MonoApiHelper.MethodSignature(mono_method)
      mono_method_cache[cacheId] = this.generateSignature(mono_signature)
    }

    return mono_method_cache[cacheId]
  }

  static generateSignature(mono_signature) {
    const params = MonoApiHelper.SignatureGetParams(mono_signature).map(MonoType.from)

    return {
      create: function(...args) {
        /*if (args.length === 4) {
          const textAddr = MonoApiHelper.StringNew(args[0])
          const durationAddr = Memory.alloc(4)
          const priorityAddr = Memory.alloc(4)
          const tiedAddr = Memory.alloc(1)
          Memory.writeFloat(durationAddr, args[1])
          Memory.writeS32(priorityAddr, args[2])
          Memory.writeS8(tiedAddr, args[3] ? 1 : 0)

          const argPtr = Memory.alloc(4*Process.pointerSize)
          Memory.writePointer(argPtr, textAddr)
          Memory.writePointer(argPtr.add(Process.pointerSize), durationAddr)
          Memory.writePointer(argPtr.add(Process.pointerSize*2), priorityAddr)
          Memory.writePointer(argPtr.add(Process.pointerSize*3), tiedAddr)
          return argPtr
        }*/

        if (args.length !== params.length) throw new Error('Expected ' + params.length + ' arguments!')
        const argsPtr = args.length > 0 ? Memory.alloc(args.length * Process.pointerSize) : NULL

        for (let i=0; i<args.length; i++) {
          const mono_object = params[i].create(args[i])
          Memory.writePointer(argsPtr.add(Process.pointerSize * i), mono_object)
        }

        return argsPtr
      }
    }
  }
}
