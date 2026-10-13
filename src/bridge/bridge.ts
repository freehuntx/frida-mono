/* eslint-disable @typescript-eslint/no-explicit-any -- managed members are only known at runtime */
import { MonoError } from '../errors'
import { construct, getField, invoke, setField } from '../invoke/invoke'
import type { Class } from '../meta/class'
import type { Event } from '../meta/event'
import type { Field } from '../meta/field'
import { findClass } from '../meta/lookup'
import type { Method } from '../meta/method'
import type { Property } from '../meta/property'
import { TypeEnum } from '../meta/constants'
import { typeObject } from '../meta/generics'
import { setWrapHooks } from '../marshal/hooks'
import { ManagedObject } from '../object/object'
import { StructView } from '../object/struct'
import { ensureThreadAttached } from '../runtime/thread'
import { inspector, managedClassOf, paramKindOf, shapeOf } from './kinds'
import { resolveOverload, type Candidate } from './overload'
import { C_SHARP_ALIASES } from './aliases'
import { CLASS, INTERNAL, classOfWrapper, internalOf } from './symbols'
import { callOriginal, override, revert, type HookFunction } from '../hook/hooks'

/** A generated JS class for a managed class: static members, `new`, `$` helpers. */
export type MonoClassWrapper = any
/** A bridge instance of a managed object or struct. */
export type MonoInstance = any

/** No overload fits the arguments, or several fit equally well. */
export class OverloadError extends MonoError {
  override name = 'OverloadError'

  constructor(
    message: string,
    readonly candidates: readonly string[]
  ) {
    super(`${message}\n  candidates:\n    ${candidates.join('\n    ')}`)
  }
}

// ---------------------------------------------------------------------------------------------------
// Members

type Member =
  | { kind: 'field'; field: Field }
  | { kind: 'property'; property: Property }
  | { kind: 'methods'; group: MethodGroup }
  | { kind: 'event'; event: Event }
  | { kind: 'nested'; klass: Class }

/** Members a class *declares* under `name` (static or instance side). Inherited ones are found via the parent's wrapper. */
function declaredMember(klass: Class, name: string, isStatic: boolean): Member | null {
  // A field-like event has a private backing field of the same name; the event wins.
  const event = klass.events.find((e) => e.name === name && e.isStatic === isStatic)
  if (event !== undefined) return { kind: 'event', event }
  const field = klass.fields.find((f) => f.name === name && f.isStatic === isStatic)
  if (field !== undefined) return { kind: 'field', field }
  const property = klass.properties.find((p) => p.name === name && p.isStatic === isStatic && p.indexParameters.length === 0)
  if (property !== undefined) return { kind: 'property', property }
  if (klass.methods.some((m) => m.name === name && m.isStatic === isStatic)) return { kind: 'methods', group: MethodGroup.of(klass, name, isStatic) }
  if (isStatic) {
    const nested = klass.nested(name)
    if (nested !== null) return { kind: 'nested', klass: nested }
  }
  return null
}

/** The nearest member named `name` along the hierarchy. */
function findMember(klass: Class, name: string, isStatic: boolean): Member | null {
  for (const c of klass.hierarchy) {
    const member = state(c).member(name, isStatic)
    if (member !== null) return member
  }
  return null
}

// ---------------------------------------------------------------------------------------------------
// Method groups and overload resolution

/** All overloads reachable under one name from a class (nearest first, overridden ones removed). */
class MethodGroup {
  static readonly #cache = new Map<string, MethodGroup>()

  readonly #resolved = new Map<string, Method>()
  #candidates?: Candidate<Method>[]

  private constructor(
    readonly klass: Class,
    readonly name: string,
    readonly isStatic: boolean
  ) {}

  static of(klass: Class, name: string, isStatic: boolean): MethodGroup {
    const key = `${klass.handle}:${name}:${isStatic}`
    let group = MethodGroup.#cache.get(key)
    if (group === undefined) {
      group = new MethodGroup(klass, name, isStatic)
      MethodGroup.#cache.set(key, group)
    }
    return group
  }

  get methods(): Method[] {
    return this.candidates.map((c) => c.method)
  }

  get candidates(): Candidate<Method>[] {
    if (this.#candidates !== undefined) return this.#candidates
    const seen = new Set<string>()
    const candidates: Candidate<Method>[] = []
    const classes = this.name === '.ctor' ? [this.klass] : this.klass.hierarchy
    for (const c of classes) {
      for (const method of c.methods) {
        if (method.name !== this.name || method.isStatic !== this.isStatic) continue
        const signature = method.parameters.map((p) => p.type.name).join(',')
        if (seen.has(signature)) continue // overridden or hidden by a nearer class
        seen.add(signature)
        candidates.push({ method, params: method.parameters.map((p) => paramKindOf(p.type)) })
      }
    }
    return (this.#candidates = candidates)
  }

  resolve(args: readonly unknown[]): Method {
    const shape = args.map(shapeOf).join('|')
    let method = this.#resolved.get(shape)
    if (method !== undefined) return method
    const result = resolveOverload(this.candidates, args, inspector)
    if (!result.ok) {
      const what = `${this.klass.fullName}.${this.name}(${args.map(describeArgument).join(', ')})`
      throw new OverloadError(result.reason === 'ambiguous' ? `Ambiguous call ${what}` : `No overload of ${what} matches`, result.candidates.map(String))
    }
    method = result.method
    // Shapes with plain objects or functions don't capture everything scoring looked at.
    if (!shape.includes('o') && !shape.includes('F')) this.#resolved.set(shape, method)
    return method
  }

  call(receiver: unknown, args: readonly unknown[]): unknown {
    ensureThreadAttached()
    let method = this.resolve(args)
    if (method.genericArity > 0) method = inferGenericMethod(method, args)
    return invoke(method, receiver === null ? null : (receiver as never), args)
  }
}

function describeArgument(value: unknown): string {
  const klass = managedClassOf(value)
  if (klass !== undefined) return klass.fullName
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  const wrapped = classOfWrapper(value)
  if (wrapped !== undefined) return `typeof(${wrapped.fullName})`
  return typeof value
}

/** Infers `T` of a generic method from arguments passed directly as `T` (like C#, for the simple cases). */
function inferGenericMethod(method: Method, args: readonly unknown[]): Method {
  const names = method.genericArgumentNames
  const inferred = new Map<string, Class>()
  method.parameters.forEach((p, i) => {
    if (p.type.typeEnum !== TypeEnum.MVAR) return
    const klass = classOfValue(args[i])
    if (klass !== undefined && !inferred.has(p.type.name)) inferred.set(p.type.name, klass)
  })
  const typeArgs = names.map((n) => inferred.get(n))
  if (typeArgs.some((c) => c === undefined)) {
    throw new MonoError(`Cannot infer the type arguments of ${method.fullName} from the arguments; call it with .$of(...types) first`)
  }
  return method.makeGeneric(...(typeArgs as Class[]))
}

function classOfValue(value: unknown): Class | undefined {
  const klass = managedClassOf(value)
  if (klass !== undefined) return klass
  const name =
    typeof value === 'string'
      ? 'System.String'
      : typeof value === 'boolean'
        ? 'System.Boolean'
        : typeof value === 'number'
          ? Number.isInteger(value)
            ? 'System.Int32'
            : 'System.Double'
          : typeof value === 'bigint'
            ? 'System.Int64'
            : null
  return name === null ? undefined : (findClass(name) ?? undefined)
}

const GROUP = Symbol('frida-mono.group')
const RECEIVER = Symbol('frida-mono.receiver')
const METHOD = Symbol('frida-mono.method')

type MethodFunction = ((...args: unknown[]) => unknown) & { [GROUP]?: MethodGroup; [RECEIVER]?: unknown; [METHOD]?: Method }

/** `$`-helpers of method functions (`Player.Spawn.$overloads`). Inherits Function.prototype, so `.call`/`.bind` work. */
const methodFunctionProto = Object.create(Function.prototype, {
  $overloads: {
    get(this: MethodFunction) {
      return (this[GROUP]?.methods ?? (this[METHOD] ? [this[METHOD]] : [])).map(String)
    }
  },
  $overload: {
    value(this: MethodFunction, ...types: unknown[]) {
      const group = requireGroup(this)
      const wanted = types.map(typeNameOf)
      const method = group.methods.find((m) => m.parameters.length === wanted.length && m.parameters.every((p, i) => typeMatches(p.type.name, wanted[i] as string)))
      if (method === undefined) throw new OverloadError(`${group.klass.fullName}.${group.name} has no overload (${wanted.join(', ')})`, group.methods.map(String))
      return methodFunctionFor(method, this[RECEIVER])
    }
  },
  $of: {
    value(this: MethodFunction, ...types: unknown[]) {
      const classes = types.map(toClass)
      const methods = this[METHOD] ? [this[METHOD]] : requireGroup(this).methods
      const generic = methods.filter((m) => m.genericArity === classes.length)
      if (generic.length === 0) throw new MonoError(`No generic overload with ${classes.length} type parameter(s): ${methods.map(String).join(', ')}`)
      if (generic.length === 1) return methodFunctionFor((generic[0] as Method).makeGeneric(...classes), this[RECEIVER])
      // Several generic overloads: resolve among the closed ones at call time.
      const closed = generic.map((m) => m.makeGeneric(...classes))
      const fn = ((...args: unknown[]) => {
        const result = resolveOverload(
          closed.map((m) => ({ method: m, params: m.parameters.map((p) => paramKindOf(p.type)) })),
          args,
          inspector
        )
        if (!result.ok) throw new OverloadError(`No overload of ${closed[0]?.name} matches`, closed.map(String))
        return invoke(result.method, (this[RECEIVER] ?? null) as never, args)
      }) as MethodFunction
      return Object.setPrototypeOf(fn, methodFunctionProto)
    }
  },
  /**
   * Replaces the method. Through an instance (`p.Jump.$override(fn)`) only that object's calls are
   * replaced; through the class or prototype (`Player.prototype.Jump.$override(fn)`), all calls.
   * `fn` gets the managed `this` (the class for static methods) and the arguments; inside it,
   * `this.Jump.$original(...)` calls the real implementation.
   */
  $override: {
    value(this: MethodFunction, fn: (...args: unknown[]) => unknown) {
      const method = hookTarget(this)
      const instance = hookInstance(this)
      const hook: HookFunction = (self, args) => fn.apply(self ?? classWrapper(method.class), args)
      override(method, hook, instance)
      console.log(`frida-mono: overrode ${method.fullName} ${instance === null ? 'for all calls' : 'for one instance'}`)
      return this
    }
  },
  /** Observes calls: `onEnter(self, args)` may change `args`; `onLeave(self, result)` may return a replacement result. */
  $attach: {
    value(this: MethodFunction, callbacks: { onEnter?(self: unknown, args: unknown[]): void; onLeave?(self: unknown, result: unknown): unknown }) {
      const method = hookTarget(this)
      override(
        method,
        (self, args) => {
          callbacks.onEnter?.call(self, self, args)
          const result = callOriginal(method, self, args)
          const replaced = callbacks.onLeave?.call(self, self, result)
          return replaced === undefined ? result : replaced
        },
        hookInstance(this)
      )
      return this
    }
  },
  /** Removes this method's hook (for this instance, when reached through one). */
  $revert: {
    value(this: MethodFunction) {
      const instance = hookInstance(this)
      revert(hookTarget(this), instance instanceof ManagedObject ? instance : null)
      return this
    }
  },
  /** Calls the original implementation (non-virtually). Meant for use inside `$override`. */
  $original: {
    value(this: MethodFunction, ...args: unknown[]) {
      const method = this[METHOD] ?? requireGroup(this).resolve(args)
      ensureThreadAttached()
      return callOriginal(method, this[RECEIVER] ?? null, args)
    }
  },
  $method: {
    get(this: MethodFunction) {
      return this[METHOD] ?? (this[GROUP]?.methods.length === 1 ? this[GROUP].methods[0] : undefined)
    }
  },
  [Symbol.toPrimitive]: {
    value(this: MethodFunction) {
      const group = this[GROUP]
      return group !== undefined ? `${group.klass.fullName}.${group.name}` : String(this[METHOD])
    }
  }
})

/** The single method a hook applies to: the overload chosen with `$overload`, or the only one. */
function hookTarget(fn: MethodFunction): Method {
  if (fn[METHOD] !== undefined) return fn[METHOD]
  const methods = requireGroup(fn).methods
  if (methods.length !== 1) throw new OverloadError(`${String(fn)} has ${methods.length} overloads: pick one with .$overload(...types) before hooking`, methods.map(String))
  return methods[0] as Method
}

/** The instance a hook is scoped to: set when the method was reached through an instance, not the class or prototype. */
function hookInstance(fn: MethodFunction): ManagedObject | StructView | null {
  return internalOf(fn[RECEIVER]) ?? null
}

function requireGroup(fn: MethodFunction): MethodGroup {
  const group = fn[GROUP]
  if (group === undefined) throw new MonoError('This function is a single overload already')
  return group
}

function methodGroupFunction(group: MethodGroup, receiver: unknown): MethodFunction {
  const fn = ((...args: unknown[]) => group.call(receiver, args)) as MethodFunction
  fn[GROUP] = group
  fn[RECEIVER] = receiver
  return Object.setPrototypeOf(fn, methodFunctionProto)
}

function methodFunctionFor(method: Method, receiver: unknown): MethodFunction {
  const fn = ((...args: unknown[]) => {
    ensureThreadAttached()
    return invoke(method, (receiver ?? null) as never, args)
  }) as MethodFunction
  fn[METHOD] = method
  fn[RECEIVER] = receiver
  return Object.setPrototypeOf(fn, methodFunctionProto)
}

function typeNameOf(type: unknown): string {
  if (typeof type === 'string') {
    const byRef = type.endsWith('&') ? '&' : ''
    const base = type.replace(/&$/, '')
    return (C_SHARP_ALIASES[base] ?? base) + byRef
  }
  return toClass(type).fullName
}

function typeMatches(actual: string, wanted: string): boolean {
  return actual === wanted || actual.replace(/\//g, '+') === wanted
}

function toClass(value: unknown): Class {
  const klass = classOfWrapper(value) ?? (value instanceof Object && 'handle' in value && 'fullName' in value ? (value as Class) : undefined)
  if (klass === undefined) throw new TypeError(`Expected a class (e.g. Mono.use('System.String')), got ${typeof value}`)
  return klass
}

// ---------------------------------------------------------------------------------------------------
// Per-class state: the wrapper, the instance prototype, member caches

interface ClassState {
  klass: Class
  wrapper: MonoClassWrapper
  prototype: object
  member(name: string, isStatic: boolean): Member | null
}

const states = new Map<string, ClassState>()

function state(klass: Class): ClassState {
  const key = klass.handle.toString()
  let s = states.get(key)
  if (s === undefined) {
    s = createState(klass)
    states.set(key, s)
  }
  return s
}

/** The generated JS class for `klass` (cached). */
export function classWrapper(klass: Class): MonoClassWrapper {
  return state(klass).wrapper
}

/** Wraps a raw object or struct as an instance of its runtime class's JS class. */
export function wrapInstance(value: ManagedObject | StructView): MonoInstance {
  const instance = Object.create(state(value.class).prototype)
  Object.defineProperty(instance, INTERNAL, { value })
  return instance
}

function createState(klass: Class): ClassState {
  const parent = klass.parent === null ? null : state(klass.parent)
  const members = { static: new Map<string, Member | null>(), instance: new Map<string, Member | null>() }
  const member = (name: string, isStatic: boolean): Member | null => {
    const cache = isStatic ? members.static : members.instance
    let m = cache.get(name)
    if (m === undefined) {
      m = declaredMember(klass, name, isStatic)
      cache.set(name, m)
    }
    return m
  }

  // Instance side: Player.prototype → MonoBehaviour.prototype → … → System.Object.prototype → instanceBase.
  const prototypeTarget = Object.create(parent === null ? instanceBase : parent.prototype)
  const prototype = new Proxy(prototypeTarget, instanceHandler(klass, member))

  // Static side: a constructible function whose prototype chain mirrors the managed one, rooted at null.
  const target = function () {} as unknown as Record<PropertyKey, unknown>
  delete target.name
  delete target.length
  target.prototype = prototype
  Object.defineProperty(target, CLASS, { value: klass })
  Object.setPrototypeOf(target, parent === null ? null : parent.wrapper)
  const wrapper = new Proxy(target, staticHandler(klass, member))

  return { klass, wrapper, prototype, member }
}

function instanceHandler(klass: Class, member: ClassState['member']): ProxyHandler<object> {
  return {
    get(target, key, receiver) {
      if (typeof key === 'symbol' || key.startsWith('$') || Object.prototype.hasOwnProperty.call(target, key)) return Reflect.get(target, key, receiver)
      const m = member(key, false)
      if (m === null) return Reflect.get(target, key, receiver)
      return readMember(m, receiver)
    },
    set(target, key, value, receiver) {
      if (typeof key === 'symbol') return Reflect.set(target, key, value, receiver)
      const m = findMember(klass, key, false)
      if (m === null) throw new TypeError(`${klass.fullName} has no instance member ${key}`)
      writeMember(m, key, value, receiver, klass)
      return true
    }
  }
}

function staticHandler(klass: Class, member: ClassState['member']): ProxyHandler<Record<PropertyKey, unknown>> {
  return {
    get(target, key, receiver) {
      if (typeof key === 'symbol') {
        if (key === Symbol.hasInstance) return (value: unknown) => isInstance(value, klass)
        if (key === Symbol.toPrimitive) return () => `class ${klass.fullName}`
        return Reflect.get(target, key, receiver)
      }
      if (key === 'prototype') return target.prototype
      if (key.startsWith('$')) return classHelper(klass, key)
      const m = member(key, true)
      if (m === null) return Reflect.get(target, key, receiver)
      return readMember(m, null)
    },
    set(_target, key, value) {
      if (typeof key === 'symbol' || key.startsWith('$')) throw new TypeError(`Cannot assign ${String(key)} on ${klass.fullName}`)
      const m = findMember(klass, key, true)
      if (m === null) throw new TypeError(`${klass.fullName} has no static member ${key}`)
      writeMember(m, key, value, null, klass)
      return true
    },
    has(target, key) {
      if (typeof key === 'symbol' || key.startsWith('$') || key === 'prototype') return Reflect.has(target, key)
      return findMember(klass, key, true) !== null
    },
    construct(_target, args) {
      return wrapInstance(newInstance(klass, args))
    },
    apply() {
      throw new TypeError(`Class constructor ${klass.fullName} cannot be invoked without 'new'`)
    }
  }
}

function readMember(m: Member, receiver: unknown): unknown {
  // Methods keep the raw receiver: the prototype itself when reached as `Player.prototype.X` (for hooks).
  if (m.kind === 'methods') return methodGroupFunction(m.group, receiver)
  if (m.kind === 'nested') return classWrapper(m.klass)
  const self = receiver === null ? null : instanceOf(receiver)
  switch (m.kind) {
    case 'field':
      return getField(m.field, self)
    case 'property': {
      const getter = m.property.getter
      if (getter === null) throw new TypeError(`Property ${m.property.name} has no getter`)
      return invoke(getter, self, [])
    }
    case 'event':
      return eventAccessor(m.event, self)
  }
}

function writeMember(m: Member, name: string, value: unknown, receiver: unknown, klass: Class): void {
  const self = receiver === null ? null : instanceOf(receiver)
  switch (m.kind) {
    case 'field':
      return setField(m.field, self, value)
    case 'property': {
      const setter = m.property.setter
      if (setter === null) throw new TypeError(`Property ${klass.fullName}.${name} is read-only`)
      invoke(setter, self, [value])
      return
    }
    case 'methods':
      throw new TypeError(`Assigning ${klass.fullName}.${name} doesn't hook it. Use .${name}.$override(fn) instead`)
    default:
      throw new TypeError(`${klass.fullName}.${name} can't be assigned`)
  }
}

function instanceOf(receiver: unknown): ManagedObject | StructView {
  const internal = internalOf(receiver)
  if (internal === undefined) throw new TypeError('Instance member accessed on something that is not a managed instance')
  return internal
}

function isInstance(value: unknown, klass: Class): boolean {
  const internal = internalOf(value)
  if (internal instanceof ManagedObject) return internal.isInstanceOf(klass)
  if (internal instanceof StructView) return internal.class === klass || klass.isAssignableFrom(internal.class)
  return false
}

function eventAccessor(event: Event, self: ManagedObject | StructView | null): { add(handler: unknown): void; remove(handler: unknown): void } {
  return {
    add(handler) {
      if (event.add === null) throw new TypeError(`Event ${event.name} has no add accessor`)
      invoke(event.add, self, [handler])
    },
    remove(handler) {
      if (event.remove === null) throw new TypeError(`Event ${event.name} has no remove accessor`)
      invoke(event.remove, self, [handler])
    }
  }
}

let unityObject: Class | null | undefined

function newInstance(klass: Class, args: readonly unknown[]): ManagedObject | StructView {
  ensureThreadAttached()
  if (klass.isGenericDefinition) throw new MonoError(`${klass.fullName} is an open generic type: close it first with .$of(...types)`)
  if (unityObject === undefined) unityObject = findClass('UnityEngine.Object')
  if (unityObject !== null && klass.isSubclassOf(unityObject, false)) {
    throw new MonoError(`${klass.fullName} is a UnityEngine.Object: create it with AddComponent / Instantiate / new GameObject instead of new`)
  }
  if (klass.isValueType && args.length === 0) return construct(klass, null)
  const group = MethodGroup.of(klass, '.ctor', false)
  if (group.methods.length === 0) throw new MonoError(`${klass.fullName} has no constructors`)
  return construct(klass, group.resolve(args), args)
}

// ---------------------------------------------------------------------------------------------------
// $ helpers

/** Prototype root of every bridge instance: `$` helpers and JS integration. */
const instanceBase: object = Object.create(null, {
  $class: {
    get() {
      return instanceOf(this).class
    }
  },
  $handle: {
    get() {
      const internal = instanceOf(this)
      return internal instanceof StructView ? internal.box.gcHandle : internal.gcHandle
    }
  },
  $pointer: {
    get() {
      const internal = instanceOf(this)
      return internal instanceof StructView ? internal.address : internal.pointer
    }
  },
  $cast: {
    value(type: unknown) {
      const klass = toClass(type)
      const internal = instanceOf(this)
      if (!isInstance(this, klass)) throw new TypeError(`${internal.class.fullName} is not a ${klass.fullName}`)
      const instance = Object.create(state(klass).prototype)
      Object.defineProperty(instance, INTERNAL, { value: internal })
      return instance
    }
  },
  $is: {
    value(type: unknown) {
      return isInstance(this, toClass(type))
    }
  },
  $equals: {
    value(other: unknown) {
      const a = instanceOf(this)
      const b = internalOf(other)
      if (a instanceof StructView || b === undefined || b instanceof StructView) return a === b
      return a.equals(b)
    }
  },
  $dispose: {
    value() {
      const internal = instanceOf(this)
      ;(internal instanceof StructView ? internal.box : internal).dispose()
    }
  },
  $field: {
    value(name: string) {
      return getField(requireField(instanceOf(this).class, name), instanceOf(this))
    }
  },
  $setField: {
    value(name: string, value: unknown) {
      setField(requireField(instanceOf(this).class, name), instanceOf(this), value)
    }
  },
  $item: {
    value(...index: unknown[]) {
      return indexer(this, 'get').call(this, index)
    }
  },
  $setItem: {
    value(...indexAndValue: unknown[]) {
      return indexer(this, 'set').call(this, indexAndValue)
    }
  },
  /** Struct fields as a plain object (structs only). */
  $value: {
    get() {
      const internal = instanceOf(this)
      if (!(internal instanceof StructView)) throw new TypeError('$value is only available on structs')
      return internal.toJSON()
    }
  },
  [Symbol.toPrimitive]: {
    value() {
      const internal = instanceOf(this)
      return internal.toString()
    }
  },
  [Symbol.iterator]: {
    *value(this: MonoInstance) {
      const klass = instanceOf(this).class
      if (findMember(klass, 'GetEnumerator', false) === null) throw new TypeError(`${klass.fullName} is not enumerable`)
      const enumerator = this.GetEnumerator()
      while (enumerator.MoveNext()) yield enumerator.Current
    }
  }
})

function requireField(klass: Class, name: string): Field {
  const field = klass.field(name)
  if (field === null) throw new TypeError(`${klass.fullName} has no field ${name}`)
  return field
}

function indexer(self: unknown, accessor: 'get' | 'set'): MethodGroup {
  const klass = instanceOf(self).class
  const group = MethodGroup.of(klass, accessor === 'get' ? 'get_Item' : 'set_Item', false)
  if (group.methods.length === 0) throw new TypeError(`${klass.fullName} has no indexer${accessor === 'set' ? ' setter' : ''}`)
  return group
}

function classHelper(klass: Class, key: string): unknown {
  switch (key) {
    case '$class':
      return klass
    case '$type':
      return wrapInstance(typeObject(klass))
    case '$methods':
      return klass.methods.map((m) => m.toJSON())
    case '$fields':
      return klass.fields.map((f) => f.toJSON())
    case '$properties':
      return klass.properties.map((p) => p.toJSON())
    case '$events':
      return klass.events.map((e) => e.toJSON())
    case '$nested':
      return klass.nestedClasses.map((c) => classWrapper(c))
    case '$generic':
      return klass.isGenericDefinition
    case '$of':
      return (...types: unknown[]) => classWrapper(klass.makeGeneric(...types.map(toClass)))
    case '$wrap':
      return (pointer: NativePointer) => (pointer.isNull() ? null : wrapInstance(new ManagedObject(pointer)))
    case '$field':
      return (name: string) => getField(requireField(klass, name))
    case '$setField':
      return (name: string, value: unknown) => setField(requireField(klass, name), null, value)
    default:
      return undefined
  }
}

// ---------------------------------------------------------------------------------------------------

setWrapHooks({
  wrapObject: wrapInstance,
  wrapStruct: wrapInstance,
  unwrap(value) {
    const internal = internalOf(value)
    if (internal !== undefined) return internal
    const klass = classOfWrapper(value)
    // A class where a System.Type is expected (`FindObjectOfType(Player)`).
    return klass === undefined ? undefined : typeObject(klass)
  }
})
