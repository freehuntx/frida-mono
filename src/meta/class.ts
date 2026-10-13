import { readUtf8 } from '../memory/strings'
import type { MonoClassFieldPtr, MonoClassPtr, MonoEventPtr, MonoMethodPtr, MonoPropertyPtr } from '../native/api.generated'
import { api } from '../native/api'
import { scoped } from '../memory/scope'
import { construct, type Instance } from '../invoke/invoke'
import { TypeAttributes, TypeEnum } from './constants'
import { Event } from './event'
import { classGenericArguments, makeGenericClass, typeObject } from './generics'
import type { ManagedObject } from '../object/object'
import { Field } from './field'
import { Image } from './image'
import { interner, iterate } from './intern'
import { Method } from './method'
import { Property } from './property'
import { Type } from './type'

/** A `MonoClass*`. Member lists (`fields`, `methods`, …) are the members *declared* by this class; lookups walk the parents. */
export class Class {
  static readonly from = interner((handle: MonoClassPtr) => new Class(handle))

  #name?: string
  #namespace?: string
  #fullName?: string
  #fields?: readonly Field[]
  #methods?: readonly Method[]
  #properties?: readonly Property[]
  #events?: readonly Event[]
  #nested?: readonly Class[]
  #interfaces?: readonly Class[]

  private constructor(readonly handle: MonoClassPtr) {}

  /** Simple name: `Player`, `List\`1`, `Inner` (for `Outer+Inner`). */
  get name(): string {
    return (this.#name ??= readUtf8(api.mono_class_get_name(this.handle)) ?? '')
  }

  /** Namespace; empty for nested classes and the global namespace. */
  get namespace(): string {
    return (this.#namespace ??= readUtf8(api.mono_class_get_namespace(this.handle)) ?? '')
  }

  /**
   * Full name in C#-like display form, with `+` for nesting: `Ns.Outer+Inner`, `Ns.Box<T>`,
   * `System.Collections.Generic.List<System.String>`, `System.Int32[]`.
   */
  get fullName(): string {
    if (this.#fullName !== undefined) return this.#fullName
    // mono_type_get_name joins nested names with '.', like namespaces; swap the nesting dot for '+'.
    const typeName = this.type.name
    const declaring = this.declaringClass
    const prefix = declaring !== null ? `${declaring.type.name}.` : ''
    return (this.#fullName = declaring !== null && typeName.startsWith(prefix) ? `${declaring.fullName}+${typeName.slice(prefix.length)}` : typeName)
  }

  get image(): Image {
    return Image.from(api.mono_class_get_image(this.handle))
  }

  /** The type of a value of this class (`byval_arg`). */
  get type(): Type {
    return Type.from(api.mono_class_get_type(this.handle))
  }

  get parent(): Class | null {
    return Class.from.orNull(api.mono_class_get_parent(this.handle))
  }

  /** The enclosing class of a nested class. */
  get declaringClass(): Class | null {
    return Class.from.orNull(api.mono_class_get_nesting_type(this.handle))
  }

  /** `TypeAttributes` flags. */
  get flags(): number {
    return api.mono_class_get_flags(this.handle)
  }

  get token(): number {
    return api.mono_class_get_type_token(this.handle)
  }

  get isValueType(): boolean {
    return api.mono_class_is_valuetype(this.handle) !== 0
  }

  get isEnum(): boolean {
    return api.mono_class_is_enum(this.handle) !== 0
  }

  get isDelegate(): boolean {
    return api.mono_class_is_delegate(this.handle) !== 0
  }

  get isInterface(): boolean {
    return (this.flags & TypeAttributes.INTERFACE) !== 0
  }

  get isAbstract(): boolean {
    return (this.flags & TypeAttributes.ABSTRACT) !== 0
  }

  get isSealed(): boolean {
    return (this.flags & TypeAttributes.SEALED) !== 0
  }

  /** A closed or partially closed generic type, e.g. `List<string>`. */
  get isGenericInstance(): boolean {
    return this.type.typeEnum === TypeEnum.GENERICINST
  }

  /** An open generic type definition, e.g. `List<T>`. (Nested classes of generic types aren't detected.) */
  get isGenericDefinition(): boolean {
    return !this.isGenericInstance && this.name.includes('`')
  }

  /** Array rank; 0 for non-arrays. */
  get rank(): number {
    return api.mono_class_get_rank(this.handle)
  }

  /** Element class of arrays and pointers, underlying class of enums; otherwise the class itself. */
  get elementClass(): Class {
    return Class.from(api.mono_class_get_element_class(this.handle))
  }

  /** Underlying integer type of an enum, or `null`. */
  get enumBaseType(): Type | null {
    return Type.from.orNull(api.mono_class_enum_basetype(this.handle))
  }

  /** Size of an instance in bytes, including the object header. */
  get instanceSize(): number {
    return api.mono_class_instance_size(this.handle)
  }

  /** Size of the unboxed value (value types), without the object header. */
  get valueSize(): number {
    return api.mono_class_value_size(this.handle, NULL)
  }

  get fields(): readonly Field[] {
    return (this.#fields ??= Object.freeze(iterate((iter) => api.mono_class_get_fields(this.handle, iter) as MonoClassFieldPtr).map((f) => Field.from(f))))
  }

  /** Declared methods, including constructors (`.ctor`, `.cctor`) and accessors (`get_X`). */
  get methods(): readonly Method[] {
    return (this.#methods ??= Object.freeze(iterate((iter) => api.mono_class_get_methods(this.handle, iter) as MonoMethodPtr).map((m) => Method.from(m))))
  }

  get properties(): readonly Property[] {
    return (this.#properties ??= Object.freeze(iterate((iter) => api.mono_class_get_properties(this.handle, iter) as MonoPropertyPtr).map((p) => Property.from(p))))
  }

  get events(): readonly Event[] {
    return (this.#events ??= Object.freeze(iterate((iter) => api.mono_class_get_events(this.handle, iter) as MonoEventPtr).map((e) => Event.from(e))))
  }

  get nestedClasses(): readonly Class[] {
    return (this.#nested ??= Object.freeze(iterate((iter) => api.mono_class_get_nested_types(this.handle, iter) as MonoClassPtr).map((c) => Class.from(c))))
  }

  /** Interfaces this class declares it implements (not inherited ones). */
  get interfaces(): readonly Class[] {
    return (this.#interfaces ??= Object.freeze(iterate((iter) => api.mono_class_get_interfaces(this.handle, iter) as MonoClassPtr).map((c) => Class.from(c))))
  }

  /** This class and its parents, nearest first. */
  get hierarchy(): Class[] {
    const chain: Class[] = [this]
    for (let c = this.parent; c !== null; c = c.parent) chain.push(c)
    return chain
  }

  /** First method named `name` (with `paramCount` parameters, if given), searching parents too. */
  method(name: string, paramCount = -1): Method | null {
    return scoped((scope) => {
      const n = scope.utf8(name)
      for (const c of this.hierarchy) {
        const m = api.mono_class_get_method_from_name(c.handle, n, paramCount)
        if (!m.isNull()) return Method.from(m)
      }
      return null
    })
  }

  /** Every method named `name` (all overloads), declared here or in a parent, nearest first. */
  methodsNamed(name: string): Method[] {
    return this.hierarchy.flatMap((c) => c.methods.filter((m) => m.name === name))
  }

  /** Field named `name`, searching parents too. */
  field(name: string): Field | null {
    return scoped((scope) => Field.from.orNull(api.mono_class_get_field_from_name(this.handle, scope.utf8(name))))
  }

  /** Property named `name`, searching parents too. */
  property(name: string): Property | null {
    return scoped((scope) => Property.from.orNull(api.mono_class_get_property_from_name(this.handle, scope.utf8(name))))
  }

  /** Event named `name`, searching parents too. */
  event(name: string): Event | null {
    for (const c of this.hierarchy) {
      const e = c.events.find((e) => e.name === name)
      if (e !== undefined) return e
    }
    return null
  }

  /** Nested class named `name` (simple name). */
  nested(name: string): Class | null {
    return this.nestedClasses.find((c) => c.name === name) ?? null
  }

  /**
   * Creates an instance with constructor `ctor` (one of `methodsNamed('.ctor')`), or the
   * parameterless one / `default(T)` when `ctor` is `null`. Returns a `ManagedObject` or, for structs, a `StructView`.
   */
  construct(ctor: Method | null = null, ...args: unknown[]): Instance {
    return construct(this, ctor, args)
  }

  /** Closes a generic type definition: `List\`1` + `[String]` → `List<String>` (cached). */
  makeGeneric(...args: Class[]): Class {
    return makeGenericClass(this, args)
  }

  /** Type arguments of a generic instance, or type parameters (as classes) of a generic definition. */
  get genericArguments(): readonly Class[] {
    return classGenericArguments(this)
  }

  /** The managed `System.Type` object for this class. */
  get reflectionType(): ManagedObject {
    return typeObject(this)
  }

  /** True if this class derives from `other` (or implements it, when `checkInterfaces`). */
  isSubclassOf(other: Class, checkInterfaces = true): boolean {
    return api.mono_class_is_subclass_of(this.handle, other.handle, checkInterfaces ? 1 : 0) !== 0
  }

  /** True if a value of class `other` can be stored in a variable of this class. */
  isAssignableFrom(other: Class): boolean {
    return api.mono_class_is_assignable_from(this.handle, other.handle) !== 0
  }

  toString(): string {
    return this.fullName
  }

  toJSON(): ClassDescriptor {
    return {
      name: this.name,
      namespace: this.namespace,
      fullName: this.fullName,
      parent: this.parent?.fullName ?? null,
      kind: this.isInterface ? 'interface' : this.isEnum ? 'enum' : this.isValueType ? 'struct' : this.isDelegate ? 'delegate' : 'class'
    }
  }
}

export interface ClassDescriptor {
  name: string
  namespace: string
  fullName: string
  parent: string | null
  kind: 'class' | 'struct' | 'enum' | 'interface' | 'delegate'
}
