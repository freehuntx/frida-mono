import { MonoApiHelper } from 'frida-mono-api'
import { IlTypes } from './constants'
import MonoClass from './MonoClass'

const PrimitiveTypeMap = {
  [IlTypes.BOOLEAN]: {
    read: addr => Memory.readS8(addr) === 1,
    write: (addr, val) => Memory.writeS8(addr, val ? 1 : 0)
  },
  [IlTypes.CHAR]: { read: Memory.readS8, write: Memory.writeS8 },
  [IlTypes.I1]: { read: Memory.readS8, write: Memory.writeS8 },
  [IlTypes.U1]: { read: Memory.readU8, write: Memory.writeU8 },
  [IlTypes.I2]: { read: Memory.readS16, write: Memory.writeS16 },
  [IlTypes.U2]: { read: Memory.readU16, write: Memory.writeU16 },
  [IlTypes.I4]: { read: Memory.readS32, write: Memory.writeS32 },
  [IlTypes.U4]: { read: Memory.readU32, write: Memory.writeU32 },
  [IlTypes.I8]: { read: Memory.readS64, write: Memory.writeS64 },
  [IlTypes.U8]: { read: Memory.readU64, write: Memory.writeU64 },
  [IlTypes.R4]: { read: Memory.readFloat, write: Memory.writeFloat },
  [IlTypes.R8]: { read: Memory.readDouble, write: Memory.writeDouble }
}

const mono_type_cache = {}
export default class MonoType {
  static from(mono_type) {
    const cacheId = mono_type.toInt32()

    if (mono_type_cache[cacheId] === undefined) {
      mono_type_cache[cacheId] = MonoType.generateType(mono_type)
    }

    return mono_type_cache[cacheId]
  }

  static fromClass(mono_class) {
    const mono_type = MonoApiHelper.ClassGetType(mono_class)
    return MonoType.from(mono_type)
  }

  static generateType(mono_type) {
    const mono_class = MonoApiHelper.ClassFromMonoType(mono_type)
    const mono_ilType = MonoApiHelper.TypeGetType(mono_type)

    return {
      create: function(value) {
        const mono_object = MonoApiHelper.ObjectNew(mono_class)
        if (value !== undefined) this.write(mono_object, value)
        return mono_object
      },
      read: function(mono_object) {
        if (PrimitiveTypeMap[mono_ilType] !== undefined) {
          return PrimitiveTypeMap[mono_ilType].read(MonoApiHelper.ObjectUnbox(mono_object))
        }
        else if (mono_ilType === IlTypes.CLASS) {
          return MonoClass.from(mono_class).$instantiate(mono_object)
        }
        else {
          throw new Error('Read not implemented for type: ' + mono_ilType)
        }
      },
      write: function(mono_object, value) {
        if (PrimitiveTypeMap[mono_ilType] !== undefined) {
          PrimitiveTypeMap[mono_ilType].write(MonoApiHelper.ObjectUnbox(mono_object), value)
        }
        else if (mono_ilType === IlTypes.CLASS) {
          // TODO: Check if boxing object is same class
          Memory.writePointer(mono_object, value)
        }
        else if (mono_ilType === IlTypes.STRING) {
          Memory.writePointer(mono_object, MonoApiHelper.StringNew(value))
        }
        else if (mono_ilType === IlTypes.VALUETYPE) {
          if (MonoApiHelper.ClassIsEnum(mono_class)) {
            const enum_type = MonoApiHelper.ClassEnumBasetype(mono_class)
            MonoType.from(enum_type).write(mono_object, value)
          }
          else {
            throw new Error('Valuetype not implemented for: ' + MonoApiHelper.ClassGetName(mono_class))
          }
        }
        else {
          throw new Error('Write not implemented for type: ' + mono_ilType)
        }
      }
    }
  }
}
