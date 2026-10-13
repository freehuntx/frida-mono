import { readUtf8, takeUtf8 } from '../memory/strings'
import type { MonoMethodPtr } from '../native/api.generated'
import { api } from '../native/api'
import { invoke, type Instance } from '../invoke/invoke'
import { Class } from './class'
import { genericMethodArgumentNames, genericMethodArity, makeGenericMethod } from './generics'
import { accessOf, MethodAttributes, MethodImplAttributes, type Access } from './constants'
import { interner } from './intern'
import { Signature } from './signature'
import type { Type } from './type'

export interface Parameter {
  readonly name: string
  readonly type: Type
  /** `ref` or `out`. */
  readonly byRef: boolean
  readonly out: boolean
}

/** A `MonoMethod*`. */
export class Method {
  static readonly from = interner((handle: MonoMethodPtr) => new Method(handle))

  #name?: string
  #flags?: number
  #implFlags?: number
  #parameters?: readonly Parameter[]

  private constructor(readonly handle: MonoMethodPtr) {}

  get name(): string {
    return (this.#name ??= readUtf8(api.mono_method_get_name(this.handle)) ?? '')
  }

  /** The declaring class. */
  get class(): Class {
    return Class.from(api.mono_method_get_class(this.handle))
  }

  get signature(): Signature {
    return Signature.from(api.mono_method_signature(this.handle))
  }

  get returnType(): Type {
    return this.signature.returnType
  }

  get parameters(): readonly Parameter[] {
    if (this.#parameters !== undefined) return this.#parameters
    const signature = this.signature
    const types = signature.parameterTypes
    const names = Memory.alloc(Math.max(types.length, 1) * Process.pointerSize)
    api.mono_method_get_param_names(this.handle, names)
    return (this.#parameters = Object.freeze(
      types.map((type, i) => ({
        name: readUtf8(names.add(i * Process.pointerSize).readPointer()) ?? `arg${i}`,
        type,
        byRef: type.isByRef,
        out: signature.isOut(i)
      }))
    ))
  }

  get parameterCount(): number {
    return this.signature.parameterCount
  }

  /** `MethodAttributes` flags. */
  get flags(): number {
    if (this.#flags === undefined) {
      const implFlags = Memory.alloc(4)
      this.#flags = api.mono_method_get_flags(this.handle, implFlags)
      this.#implFlags = implFlags.readU32()
    }
    return this.#flags
  }

  /** `MethodImplAttributes` flags. */
  get implFlags(): number {
    void this.flags
    return this.#implFlags ?? 0
  }

  get token(): number {
    return api.mono_method_get_token(this.handle)
  }

  get access(): Access {
    return accessOf(this.flags)
  }

  get isStatic(): boolean {
    return (this.flags & MethodAttributes.STATIC) !== 0
  }

  get isVirtual(): boolean {
    return (this.flags & MethodAttributes.VIRTUAL) !== 0
  }

  get isAbstract(): boolean {
    return (this.flags & MethodAttributes.ABSTRACT) !== 0
  }

  /** `.ctor` or `.cctor`. */
  get isConstructor(): boolean {
    return this.name === '.ctor' || this.name === '.cctor'
  }

  /** Implemented in the runtime (`[MethodImpl(InternalCall)]`) or as P/Invoke, so it has no IL. */
  get isNative(): boolean {
    return (this.implFlags & MethodImplAttributes.INTERNAL_CALL) !== 0 || (this.flags & MethodAttributes.PINVOKE_IMPL) !== 0
  }

  /**
   * Calls the method (`instance` is `null` for static methods). Instance calls dispatch virtually.
   * `ref`/`out` parameters take a `Mono.ref()`.
   */
  invoke(instance: Instance | null, ...args: unknown[]): unknown {
    return invoke(this, instance, args)
  }

  /** Number of type parameters of a generic method definition (`Map<U>` → 1); 0 otherwise. */
  get genericArity(): number {
    return genericMethodArity(this)
  }

  /** Type parameter names of a generic method definition (`Map<U>` → `['U']`). */
  get genericArgumentNames(): readonly string[] {
    return genericMethodArgumentNames(this)
  }

  /** Closes a generic method definition with type arguments (cached). */
  makeGeneric(...args: Class[]): Method {
    return makeGenericMethod(this, args, (handle) => Method.from(handle))
  }

  /** Mono's description: `Ns.Class:Name (int,string)`. */
  get fullName(): string {
    return takeUtf8(api.mono_method_full_name(this.handle, 1)) ?? this.name
  }

  toString(): string {
    return this.fullName
  }

  toJSON(): MethodDescriptor {
    return {
      name: this.name,
      static: this.isStatic,
      access: this.access,
      virtual: this.isVirtual,
      abstract: this.isAbstract,
      returns: this.returnType.name,
      params: this.parameters.map((p) => ({ name: p.name, type: p.type.name, byRef: p.byRef, out: p.out }))
    }
  }
}

export interface MethodDescriptor {
  name: string
  static: boolean
  access: Access
  virtual: boolean
  abstract: boolean
  returns: string
  params: { name: string; type: string; byRef: boolean; out: boolean }[]
}
