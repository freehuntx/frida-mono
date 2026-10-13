import { MonoError } from '../errors'
import { Scope, scoped } from '../memory/scope'
import type { Class } from '../meta/class'
import { TypeEnum } from '../meta/constants'
import type { Method } from '../meta/method'
import type { Type } from '../meta/type'
import { api } from '../native/api'
import { fromObject, marshallerFor, toObject } from '../marshal/marshaller'
import { hooks } from '../marshal/hooks'
import { EnumValue } from '../object/enum'
import { freeHandle, newHandle } from '../object/handles'
import { Ref } from '../object/ref'
import { StructView } from '../object/struct'
import type { MonoObjectPtr } from '../native/api.generated'

/**
 * Native view of a managed signature, for `Interceptor.replace` on JIT code.
 *
 * Mono's managed calling convention (mini-amd64.c, `add_valuetype`) matches the C ABI for `this`,
 * references (pointers) and primitives, but not for structs. On x64 SysV:
 * - struct arguments ≤ 16 bytes go in one or two *integer* registers, even if they hold floats;
 *   bigger ones are copied onto the stack. Both match passing them as 8-byte integer chunks.
 * - struct return values of exactly 8 bytes come back in RAX; all others are written to a hidden
 *   return-buffer argument, passed after `this` (or after a first argument of reference type),
 *   otherwise first.
 * Struct hooks are limited to x64 SysV, where e2e tests verify this. Signatures that can't be
 * represented are rejected when the hook is installed (see {@link unsupportedReason}).
 */

type Raw = unknown
type NativeType = NativeCallbackArgumentType

interface ValueCodec {
  native: NativeType
  /** Native value (as Frida hands it to a NativeCallback) → JS. */
  toJs(raw: Raw): unknown
  /** JS → native value (as a NativeCallback returns it). */
  toNative(value: unknown): Raw
}

export interface DecodedCall {
  self: unknown
  args: unknown[]
  /** Writes changed `Ref` values back to the caller's variables. */
  writeBack(): void
  /** The native return value for `value`. */
  encodeReturn(value: unknown): Raw
  /** The native return value when the hook failed (zero / NULL / zeroed struct). */
  defaultReturn(): Raw
}

export interface NativeSignature {
  ret: NativeCallbackReturnType
  args: NativeCallbackArgumentType[]
  /** Converts the callback's raw arguments into JS values (byref args become `Ref`s) and back. */
  decode(raw: Raw[]): DecodedCall
  /** The return value to use when a hook fails before decoding. */
  readonly defaultReturn: Raw
}

const PRIMITIVE_NATIVE: Partial<Record<number, NativeType>> = {
  [TypeEnum.BOOLEAN]: 'uint8',
  [TypeEnum.CHAR]: 'uint16',
  [TypeEnum.I1]: 'int8',
  [TypeEnum.U1]: 'uint8',
  [TypeEnum.I2]: 'int16',
  [TypeEnum.U2]: 'uint16',
  [TypeEnum.I4]: 'int32',
  [TypeEnum.U4]: 'uint32',
  [TypeEnum.I8]: 'int64',
  [TypeEnum.U8]: 'uint64',
  [TypeEnum.R4]: 'float',
  [TypeEnum.R8]: 'double',
  [TypeEnum.I]: 'pointer',
  [TypeEnum.U]: 'pointer',
  [TypeEnum.PTR]: 'pointer',
  [TypeEnum.FNPTR]: 'pointer'
}

/** Recently returned objects stay pinned until the hooking thread is back in managed code. */
function keepUntilNextTick(object: NativePointer): void {
  if (object.isNull()) return
  const handle = newHandle(object as MonoObjectPtr)
  setTimeout(() => freeHandle(handle), 0)
}

/** A scope whose pins and buffers outlive the hook's return into managed code. */
function tickScope(): Scope {
  const scope = new Scope()
  setTimeout(() => scope.dispose(), 0)
  return scope
}

function primitiveCodec(type: Type, native: NativeType): ValueCodec {
  const t = type.typeEnum
  switch (t) {
    case TypeEnum.BOOLEAN:
      return { native, toJs: (r) => (r as number) !== 0, toNative: (v) => (v ? 1 : 0) }
    case TypeEnum.CHAR:
      return { native, toJs: (r) => String.fromCharCode(r as number), toNative: (v) => (typeof v === 'string' ? v.charCodeAt(0) : Number(v)) }
    case TypeEnum.I8:
      return { native, toJs: (r) => BigInt((r as Int64).toString()), toNative: (v) => int64(String(v)) }
    case TypeEnum.U8:
      return { native, toJs: (r) => BigInt((r as UInt64).toString()), toNative: (v) => uint64(String(v)) }
    case TypeEnum.I:
    case TypeEnum.U:
    case TypeEnum.PTR:
    case TypeEnum.FNPTR:
      return { native, toJs: (r) => r, toNative: (v) => (v instanceof NativePointer ? v : ptr(String(v ?? 0))) }
    default:
      return { native, toJs: (r) => r, toNative: (v) => Number(v instanceof EnumValue ? v.value : v) }
  }
}

const STRUCTS_SUPPORTED = Process.arch === 'x64' && Process.platform !== 'windows'

/** A struct as Mono's managed ABI moves it: whole 8-byte integer chunks (see the module comment). */
function chunkCodec(type: Type, klass: Class): ValueCodec {
  const size = klass.valueSize
  const chunks = Math.max(1, Math.ceil(size / 8))
  const native: NativeType[] = Array.from({ length: chunks }, () => 'uint64' as NativeType)
  return {
    native,
    toJs(raw) {
      const buffer = Memory.alloc(chunks * 8)
      ;(raw as UInt64[]).forEach((chunk, i) => buffer.add(i * 8).writeU64(chunk))
      return hooks.wrapStruct(StructView.copyOf(klass, buffer))
    },
    toNative(value) {
      const scope = tickScope()
      const buffer = scope.alloc(chunks * 8)
      marshallerFor(type).write(buffer, value, scope)
      return Array.from({ length: chunks }, (_, i) => buffer.add(i * 8).readU64())
    }
  }
}

function codecFor(type: Type): ValueCodec | string {
  const t = type.typeEnum
  const primitive = PRIMITIVE_NATIVE[t]
  if (primitive !== undefined) return primitiveCodec(type, primitive)
  if (t === TypeEnum.VAR || t === TypeEnum.MVAR) return 'open generic parameter'
  const klass = type.class
  if (klass.isEnum) {
    const base = type.underlying
    const inner = codecFor(base)
    if (typeof inner === 'string') return inner
    return { native: inner.native, toJs: (r) => new EnumValue(klass, inner.toJs(r) as number | bigint), toNative: (v) => inner.toNative(EnumValue.parse(klass, v).value) }
  }
  if (klass.isValueType) {
    if (klass.namespace === 'System' && klass.name === 'Nullable`1') return 'Nullable<T> parameters are not supported in hooks yet'
    if (!STRUCTS_SUPPORTED) return `struct hooks (${klass.fullName}) are only verified on x64 Linux/macOS so far`
    return chunkCodec(type, klass)
  }
  // Reference types: the object pointer.
  return {
    native: 'pointer',
    toJs: (r) => fromObject(r as NativePointer),
    toNative(value) {
      const object = toObject(value, klass)
      keepUntilNextTick(object)
      return object
    }
  }
}

function byRefCodec(type: Type): { native: NativeType; toJs(raw: Raw): Ref; writeBack(raw: Raw, ref: Ref, initial: unknown): void } | string {
  const target = type.class.type
  const m = marshallerFor(target)
  return {
    native: 'pointer',
    toJs: (raw) => new Ref(m.read(raw as NativePointer)),
    writeBack(raw, ref, initial) {
      if (ref.value === initial) return
      const slot = raw as NativePointer
      if (m.isReference) {
        const object = toObject(ref.value, target.class)
        api.mono_gc_wbarrier_generic_store(slot, object as MonoObjectPtr)
      } else {
        scoped((scope) => api.mono_value_copy(slot, m.toStorage(ref.value, scope), target.class.handle))
      }
    }
  }
}

/** Why a method can't be hooked, or `null`. */
export function unsupportedReason(method: Method): string | null {
  if (method.isNative) return 'it is an internal call or P/Invoke without managed code'
  if (method.class.isGenericDefinition || method.genericArity > 0) return 'it is an open generic method'
  if (method.class.isGenericInstance) return 'methods of generic types may use shared code with a hidden context argument (not supported yet)'
  if (method.isAbstract) return 'it is abstract (hook the overriding method instead)'
  const types = [method.returnType, ...method.parameters.map((p) => p.type)]
  for (const type of types) {
    if (type.isVoid || type.isByRef) continue
    const codec = codecFor(type)
    if (typeof codec === 'string') return codec
  }
  return null
}

export function nativeSignature(method: Method): NativeSignature {
  const reason = unsupportedReason(method)
  if (reason !== null) throw new MonoError(`Cannot hook ${method.fullName}: ${reason}`)

  const self = method.isStatic ? null : method.class
  const params = method.parameters.map((p) => {
    if (p.byRef) {
      const codec = byRefCodec(p.type)
      if (typeof codec === 'string') throw new MonoError(`Cannot hook ${method.fullName}: ${codec}`)
      return { byRef: true as const, codec }
    }
    return { byRef: false as const, codec: codecFor(p.type) as ValueCodec }
  })
  const retType = method.returnType
  const ret = retType.isVoid ? null : (codecFor(retType) as ValueCodec)
  // Struct results other than 8 bytes go through a hidden return buffer (see the module comment).
  const vret = ret !== null && Array.isArray(ret.native) && retType.class.valueSize !== 8 ? retType.class : null

  const args: NativeType[] = []
  if (self !== null) args.push('pointer')
  for (const p of params) args.push(p.codec.native)
  let vretIndex = -1
  if (vret !== null) {
    const firstIsReference = method.parameters[0] !== undefined && !method.parameters[0].byRef && method.parameters[0].type.isReference
    vretIndex = self !== null || firstIsReference ? 1 : 0
    args.splice(vretIndex, 0, 'pointer')
  }

  const zero = (native: NativeType): Raw =>
    Array.isArray(native) ? native.map(zero) : native === 'pointer' ? NULL : native === 'int64' ? int64(0) : native === 'uint64' ? uint64(0) : 0

  return {
    ret: ret === null ? 'void' : vret !== null ? 'pointer' : (ret.native as NativeCallbackReturnType),
    args,
    defaultReturn: ret === null ? undefined : vret !== null ? NULL : zero(ret.native),
    decode(raw) {
      let buffer: NativePointer | null = null
      if (vretIndex >= 0) {
        buffer = raw[vretIndex] as NativePointer
        raw = raw.filter((_, i) => i !== vretIndex)
      }
      let i = 0
      let thisValue: unknown = undefined
      if (self !== null) {
        const pointer = raw[i++] as NativePointer
        // Value-type methods get a pointer to the unboxed value.
        thisValue = self.isValueType ? hooks.wrapStruct(StructView.copyOf(self, pointer)) : fromObject(pointer)
      }
      const refs: (() => void)[] = []
      const values = params.map((p) => {
        const r = raw[i++]
        if (!p.byRef) return p.codec.toJs(r)
        const ref = p.codec.toJs(r)
        const initial = ref.value
        refs.push(() => p.codec.writeBack(r, ref, initial))
        return ref
      })
      return {
        self: thisValue,
        args: values,
        writeBack: () => refs.forEach((w) => w()),
        encodeReturn(value) {
          if (ret === null) return undefined
          if (buffer === null || vret === null) return ret.toNative(value)
          const target = buffer
          scoped((scope) => api.mono_value_copy(target, marshallerFor(retType).toStorage(value, scope), vret.handle))
          return target
        },
        defaultReturn() {
          if (buffer !== null && vret !== null) {
            Memory.copy(buffer, Memory.alloc(vret.valueSize), vret.valueSize)
            return buffer
          }
          return ret === null ? undefined : zero(ret.native)
        }
      }
    }
  }
}
