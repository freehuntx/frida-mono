import { MonoError } from '../errors'
import { scoped } from '../memory/scope'
import type { Class } from '../meta/class'
import type { Field } from '../meta/field'
import type { Method } from '../meta/method'
import type { MonoMethodPtr, MonoObjectPtr, MonoVTablePtr } from '../native/api.generated'
import { api } from '../native/api'
import { marshallerFor, unboxedOffset, type Marshaller } from '../marshal/marshaller'
import { ensureThreadAttached } from '../runtime/thread'
import { pinFor } from '../object/handles'
import { ManagedError } from '../object/managed-error'
import { ManagedObject } from '../object/object'
import { Ref } from '../object/ref'
import { StructView } from '../object/struct'
import { hooks } from '../marshal/hooks'

/** The `this` of an instance call or field access. */
export type Instance = ManagedObject | StructView

interface Plan {
  params: { marshaller: Marshaller; byRef: boolean; out: boolean; name: string }[]
  ret: Marshaller
}

const plans = new Map<string, Plan>()

/** Signature turned into marshallers once per method. */
function planFor(method: Method): Plan {
  const key = method.handle.toString()
  let plan = plans.get(key)
  if (plan === undefined) {
    if (method.class.isGenericDefinition)
      throw new MonoError(`${method.fullName} belongs to the open generic type ${method.class.fullName}: close it first (Class.makeGeneric / $of)`)
    if (method.genericArity > 0) throw new MonoError(`${method.fullName} is a generic method definition: close it first (Method.makeGeneric / $of)`)
    plan = {
      params: method.parameters.map((p) => ({
        // A byref parameter's slot holds a value of the referenced type.
        marshaller: marshallerFor(p.byRef ? p.type.class.type : p.type),
        byRef: p.byRef,
        out: p.out,
        name: p.name
      })),
      ret: marshallerFor(method.returnType)
    }
    plans.set(key, plan)
  }
  return plan
}

/**
 * Calls `method` through `mono_runtime_invoke`. Instance calls dispatch virtually like C# does.
 * `ref`/`out` parameters take a `Mono.ref()`, whose `.value` is updated after the call. A managed
 * exception is rethrown as {@link ManagedError}.
 */
export interface InvokeOptions {
  /** Dispatch instance calls virtually like C# (default). `false` calls exactly `method`, e.g. a hook's original. */
  virtual?: boolean
}

export function invoke(method: Method, instance: Instance | null, args: readonly unknown[], options: InvokeOptions = {}): unknown {
  ensureThreadAttached()
  const plan = planFor(method)
  if (args.length !== plan.params.length) {
    throw new MonoError(`${method.fullName} takes ${plan.params.length} argument(s), got ${args.length}`)
  }

  return scoped((scope) => {
    const params = scope.alloc(Math.max(plan.params.length, 1) * Process.pointerSize)
    const writeBacks: (() => void)[] = []

    plan.params.forEach((p, i) => {
      const value = args[i]
      let pointer: NativePointer
      if (p.byRef) {
        if (!(value instanceof Ref)) throw new TypeError(`Parameter ${p.name} of ${method.fullName} is ${p.out ? 'out' : 'ref'}: pass Mono.ref(${p.out ? '' : 'value'})`)
        const slot = scope.alloc(p.marshaller.size)
        if (!p.out && value.value !== undefined) p.marshaller.write(slot, value.value, scope)
        writeBacks.push(() => (value.value = p.marshaller.read(slot)))
        pointer = slot
      } else {
        pointer = p.marshaller.toArgument(value, scope)
      }
      params.add(i * Process.pointerSize).writePointer(pointer)
    })

    let target = method.handle
    let self: NativePointer = NULL
    if (!method.isStatic) {
      if (instance === null || instance === undefined) throw new MonoError(`${method.fullName} is an instance method: pass the instance`)
      instance = asInstance(instance)
      const boxed = pinFor(instance instanceof StructView ? instance.box.pointer : instance.pointer, scope)
      if (method.isVirtual && options.virtual !== false) target = api.mono_object_get_virtual_method(boxed, method.handle)
      // Value-type methods take a pointer to the unboxed value.
      self = api.mono_class_is_valuetype(api.mono_method_get_class(target)) !== 0 ? api.mono_object_unbox(boxed) : boxed
    }

    const exception = scope.out()
    const result = api.mono_runtime_invoke(target as MonoMethodPtr, self, params, exception)
    const thrown = exception.readPointer()
    if (!thrown.isNull()) throw new ManagedError(thrown as MonoObjectPtr)

    for (const writeBack of writeBacks) writeBack()
    return plan.ret.fromReturn(result)
  })
}

/** The class's vtable in the current domain, with its static constructor run. */
export function initializedVTable(klass: Class): MonoVTablePtr {
  const vtable = api.mono_class_vtable(api.mono_domain_get(), klass.handle)
  if (vtable.isNull()) throw new MonoError(`Could not create the vtable of ${klass.fullName}`)
  api.mono_runtime_class_init(vtable)
  return vtable
}

/** Accepts bridge instances as well as raw `ManagedObject`/`StructView`. */
function asInstance(value: unknown): Instance {
  const unwrapped = hooks.unwrap(value) ?? value
  if (unwrapped instanceof ManagedObject || unwrapped instanceof StructView) return unwrapped
  throw new TypeError('Expected a managed object or struct as the instance')
}

function instanceFieldAddress(field: Field, instance: Instance | null): NativePointer {
  if (instance === null || instance === undefined) throw new MonoError(`${field.name} is an instance field: pass the instance`)
  instance = asInstance(instance)
  if (instance instanceof StructView) return instance.address.add(unboxedOffset(field.offset))
  return instance.pointer.add(field.offset)
}

/** Reads a field. Static fields (and `const`s) ignore `instance`. */
export function getField(field: Field, instance: Instance | null = null): unknown {
  ensureThreadAttached()
  const m = marshallerFor(field.type)
  if (field.isStatic) {
    return scoped((scope) => {
      const slot = scope.alloc(m.size)
      api.mono_field_static_get_value(initializedVTable(field.class), field.handle, slot)
      return m.read(slot)
    })
  }
  return m.read(instanceFieldAddress(field, instance))
}

/** Writes a field through the runtime, so the GC sees reference stores. */
export function setField(field: Field, instance: Instance | null, value: unknown): void {
  ensureThreadAttached()
  if (field.isLiteral) throw new MonoError(`${field.name} is a const and has no storage`)
  const m = marshallerFor(field.type)
  scoped((scope) => {
    const argument = m.toStorage(value, scope)
    if (field.isStatic) return api.mono_field_static_set_value(initializedVTable(field.class), field.handle, argument)
    if (instance === null || instance === undefined) throw new MonoError(`${field.name} is an instance field: pass the instance`)
    instance = asInstance(instance)
    const object = instance instanceof StructView ? instance.box.pointer : instance.pointer
    api.mono_field_set_value(object, field.handle, argument)
  })
}

/**
 * Creates an instance of `klass` and runs `ctor` with `args`. Without `ctor`, runs the
 * parameterless constructor (reference types) or returns `default(T)` (structs).
 */
export function construct(klass: Class, ctor: Method | null, args: readonly unknown[] = []): Instance {
  ensureThreadAttached()
  if (ctor !== null && (ctor.name !== '.ctor' || !ctor.class.handle.equals(klass.handle))) throw new MonoError(`${ctor.fullName} is not a constructor of ${klass.fullName}`)
  if (klass.isValueType) {
    const view = StructView.zero(klass)
    if (ctor !== null) invoke(ctor, view, args)
    return view
  }
  if (klass.isAbstract) throw new MonoError(`Cannot create an instance of abstract ${klass.isInterface ? 'interface' : 'class'} ${klass.fullName}`)
  initializedVTable(klass)
  const pointer = api.mono_object_new(api.mono_domain_get(), klass.handle)
  if (pointer.isNull()) throw new MonoError(`Could not allocate ${klass.fullName}`)
  const object = new ManagedObject(pointer)
  if (ctor !== null) invoke(ctor, object, args)
  else {
    const parameterless = klass.method('.ctor', 0)
    if (parameterless === null || !parameterless.class.handle.equals(klass.handle)) throw new MonoError(`${klass.fullName} has no parameterless constructor`)
    invoke(parameterless, object, [])
  }
  return object
}
