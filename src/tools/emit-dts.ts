import type { DumpModel, MethodModel, TypeModel, TypeRef } from './model'

/**
 * Emits TypeScript typings for the bridge from a {@link DumpModel}.
 *
 * The output is a module that augments frida-mono's `MonoNamespaces` and `MonoTypes`, so
 * `Mono.namespaces.Game.Player` and `Mono.use('Game.Player')` become typed. Rules:
 * - Classes extend their managed parent (or `MonoObject`); `instanceof` and assignability follow C#.
 * - A method is one property listing every overload reachable from the class (like the bridge's
 *   overload resolution), so derived classes stay assignable to their bases.
 * - Parameters accept what the marshaller accepts (`long` → `number | bigint`, structs → plain
 *   objects, enums → names and numbers); results are what it returns.
 * - Types outside the dump become `MonoObject` (or `EnumValue` for enums).
 * - frida-mono's helper types are imported as `$MonoObject`, `$MonoMethod`, …: no C# type can have
 *   those names, so assemblies with their own `MonoMethod` (corlib's System.Reflection) can't shadow them.
 */

type Mode = 'in' | 'out'

const ROOT = '__mono'
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/
const RESERVED = new Set(
  'break case catch class const continue debugger default delete do else enum export extends false finally for function if import in instanceof new null return super switch this throw true try typeof var void while with yield let static implements interface package private protected public await'.split(
    ' '
  )
)

function isIdentifier(name: string): boolean {
  return IDENTIFIER.test(name) && !RESERVED.has(name)
}

function propertyName(name: string): string {
  return IDENTIFIER.test(name) ? name : JSON.stringify(name)
}

export function emitDts(model: DumpModel): string {
  const byKey = new Map(model.types.map((t) => [t.key, t]))

  /** TS name of a type within its container: arity suffix only where a non-generic sibling has the same name. */
  const tsNames = new Map<string, string>()
  const siblings = new Map<string, TypeModel[]>()
  for (const t of model.types) {
    const container = `${t.declaringType ?? t.namespace}\u0000${t.name}`
    siblings.set(container, [...(siblings.get(container) ?? []), t])
  }
  for (const group of siblings.values()) {
    for (const t of group) tsNames.set(t.key, group.length > 1 && t.genericParams.length > 0 ? `${t.name}_${t.genericParams.length}` : t.name)
  }

  const emittable = (t: TypeModel): boolean => {
    const name = tsNames.get(t.key) ?? t.name
    if (!isIdentifier(name)) return false
    if (t.namespace !== '' && !t.namespace.split('.').every(isIdentifier)) return false
    if (t.declaringType !== null) {
      const outer = byKey.get(t.declaringType)
      return outer !== undefined && emittable(outer)
    }
    return true
  }
  const types = model.types.filter(emittable)
  const included = new Set(types.map((t) => t.key))

  const pathOf = (key: string): string => {
    const t = byKey.get(key) as TypeModel
    const name = tsNames.get(key) as string
    if (t.declaringType !== null) return `${pathOf(t.declaringType)}.${name}`
    return [ROOT, ...(t.namespace === '' ? [] : t.namespace.split('.')), name].join('.')
  }

  // ------------------------------------------------------------------------------------------------
  // Type references

  const paren = (s: string): string => (s.includes('|') || s.includes('=>') ? `(${s})` : s)

  const ts = (ref: TypeRef, mode: Mode, generics: ReadonlySet<string>): string => {
    switch (ref.kind) {
      case 'void':
        return 'void'
      case 'generic':
        return generics.has(ref.name) ? ref.name : 'any'
      case 'pointer':
        return 'NativePointer'
      case 'byref':
        return `$Ref<${ts(ref.type, 'out', generics)}>`
      case 'nullable':
        return `${ts(ref.type, mode, generics)} | null`
      case 'array': {
        const out = `$MArray<${ts(ref.element, 'out', generics)}>`
        return mode === 'out' ? out : `${out} | ${paren(ts(ref.element, 'in', generics))}[] | null`
      }
      case 'primitive':
        switch (ref.name) {
          case 'bool':
            return 'boolean'
          case 'char':
            return 'string'
          case 'long':
          case 'ulong':
            return mode === 'out' ? 'bigint' : 'number | bigint'
          case 'nint':
          case 'nuint':
            return 'NativePointer'
          case 'string':
            return mode === 'out' ? 'string' : 'string | null'
          case 'object':
            return mode === 'out' ? 'any' : 'unknown'
          case 'type':
            return mode === 'out' ? '$MonoObject' : '$MonoClassLike | $MonoObject'
          default:
            return 'number'
        }
      case 'type': {
        const target = byKey.get(ref.key)
        if (target === undefined || !included.has(ref.key)) {
          if (ref.shape === 'enum') return mode === 'out' ? '$EnumValue' : '$EnumValue | number | string'
          if (mode === 'out') return '$MonoObject'
          return ref.shape === 'struct' ? '$MonoObject | Record<string, unknown>' : '$MonoObject | null'
        }
        const args = target.genericParams.length > 0 && ref.args.length === target.genericParams.length ? `<${ref.args.map((a) => ts(a, 'out', generics)).join(', ')}>` : ''
        const path = pathOf(ref.key) + args
        if (mode === 'out') return path
        switch (target.kind) {
          case 'enum': {
            const names = target.enumValues.slice(0, 64).map((v) => JSON.stringify(v.name))
            return [path, 'number', ...names].join(' | ')
          }
          case 'struct': {
            const fields = target.fields.filter((f) => !f.static && isIdentifier(f.name)).map((f) => `${f.name}?: ${ts(f.type, 'in', generics)}`)
            return `${path} | { ${fields.join('; ')} }`
          }
          case 'interface':
          case 'delegate':
            return `${path} | $MonoObject | null`
          default:
            return `${path} | null`
        }
      }
    }
  }

  // ------------------------------------------------------------------------------------------------
  // Members

  const parameters = (m: MethodModel, scope: ReadonlySet<string>): string => {
    const used = new Set<string>()
    const params = m.params.map((p, i) => {
      let name = isIdentifier(p.name) ? p.name : `arg${i}`
      if (used.has(name)) name = `${name}${i}`
      used.add(name)
      return `${name}: ${ts(p.type, 'in', scope)}`
    })
    return `(${params.join(', ')})`
  }

  const signature = (m: MethodModel, generics: ReadonlySet<string>): string => {
    const scope = new Set([...generics, ...m.genericParams])
    const typeParams = m.genericParams.length > 0 ? `<${m.genericParams.map((g) => `${g} = any`).join(', ')}>` : ''
    return `${typeParams}${parameters(m, scope)}: ${ts(m.returns, 'out', scope)}`
  }

  /** Overloads named `name` reachable from `t` (nearest first, deduped by parameter types), like the bridge's method groups. */
  const overloads = (t: TypeModel, name: string, isStatic: boolean): { method: MethodModel; owner: TypeModel }[] => {
    const seen = new Set<string>()
    const result: { method: MethodModel; owner: TypeModel }[] = []
    for (let c: TypeModel | undefined = t; c !== undefined; c = c.parent?.kind === 'type' ? byKey.get(c.parent.key) : undefined) {
      for (const m of c.methods) {
        if (m.name !== name || m.static !== isStatic) continue
        const key = JSON.stringify(m.params.map((p) => p.type))
        if (seen.has(key)) continue
        seen.add(key)
        result.push({ method: m, owner: c })
      }
    }
    return result
  }

  /**
   * The type of a field/property, or `any` when it hides an ancestor member of a different type
   * (C# `new`): TS requires derived members to be assignable to the base's, and `any` is.
   */
  const valueType = (t: TypeModel, name: string, isStatic: boolean, rendered: string): string => {
    for (let c = t.parent?.kind === 'type' ? byKey.get(t.parent.key) : undefined; c !== undefined; c = c.parent?.kind === 'type' ? byKey.get(c.parent.key) : undefined) {
      if (!included.has(c.key)) break
      const inherited = [...c.fields, ...c.properties.filter((p) => p.index.length === 0)].find((m) => m.name === name && m.static === isStatic)
      if (inherited !== undefined) return ts(inherited.type, 'out', isStatic ? new Set() : new Set(c.genericParams)) === rendered ? rendered : 'any'
    }
    return rendered
  }

  const emitMembers = (t: TypeModel, indent: string): string[] => {
    const generics = new Set(t.genericParams)
    const lines: string[] = []
    const taken = new Set<string>()
    const claim = (name: string, isStatic: boolean): boolean => {
      const key = `${isStatic ? 'static ' : ''}${name}`
      if (taken.has(key) || name === 'constructor' || (isStatic && name === 'prototype')) return false
      taken.add(key)
      return true
    }

    if (t.kind === 'enum') {
      lines.push(`${indent}private readonly __enum_${t.key.replace(/\W/g, '_')}: void`)
      for (const v of t.enumValues) if (claim(v.name, true)) lines.push(`${indent}static readonly ${propertyName(v.name)}: ${pathOf(t.key)}`)
      return lines
    }

    // Constructors (none emitted = not constructible from JS, e.g. static classes).
    const ctors = t.constructors.filter((c) => !c.static)
    if (t.kind === 'struct' && !ctors.some((c) => c.params.length === 0)) lines.push(`${indent}constructor()`)
    for (const c of ctors) lines.push(`${indent}constructor${parameters(c, generics)}`)
    if (ctors.length === 0 && t.kind !== 'struct') lines.push(`${indent}protected constructor()`)

    // Events first: a field-like event's backing field has the same name.
    for (const e of t.events) {
      if (claim(e.name, e.static)) lines.push(`${indent}${e.static ? 'static ' : ''}readonly ${propertyName(e.name)}: $MonoEvent`)
    }
    for (const f of t.fields) {
      if (!claim(f.name, f.static)) continue
      const type = valueType(t, f.name, f.static, ts(f.type, 'out', f.static ? new Set() : generics))
      lines.push(`${indent}${f.static ? 'static ' : ''}${f.readonly || f.literal ? 'readonly ' : ''}${propertyName(f.name)}: ${type}`)
    }
    for (const p of t.properties) {
      if (p.index.length > 0 || !claim(p.name, p.static)) continue
      const type = valueType(t, p.name, p.static, ts(p.type, 'out', p.static ? new Set() : generics))
      lines.push(`${indent}${p.static ? 'static ' : ''}${p.set ? '' : 'readonly '}${propertyName(p.name)}: ${type}`)
    }
    const groups = new Map<string, boolean>()
    for (const m of t.methods) groups.set(`${m.static ? 's' : 'i'}${m.name}`, m.static)
    for (const [key, isStatic] of groups) {
      const name = key.slice(1)
      if (!claim(name, isStatic)) continue
      const scope = isStatic ? new Set<string>() : generics
      const sigs = overloads(t, name, isStatic).map(({ method }) => signature(method, scope))
      lines.push(`${indent}${isStatic ? 'static ' : ''}${propertyName(name)}: $MonoMethod<{ ${sigs.map((s) => `${s};`).join(' ')} }>`)
    }
    return lines
  }

  // ------------------------------------------------------------------------------------------------
  // Containers

  const nestedOf = new Map<string, TypeModel[]>()
  const byNamespace = new Map<string, TypeModel[]>()
  for (const t of types) {
    if (t.declaringType !== null) nestedOf.set(t.declaringType, [...(nestedOf.get(t.declaringType) ?? []), t])
    else byNamespace.set(t.namespace, [...(byNamespace.get(t.namespace) ?? []), t])
  }

  const emitType = (t: TypeModel, indent: string): string[] => {
    const name = tsNames.get(t.key) as string
    const typeParams = t.genericParams.length > 0 ? `<${t.genericParams.map((g) => `${g} = any`).join(', ')}>` : ''
    let base = '$MonoObject'
    if (t.kind === 'enum') base = '$EnumValue'
    else if (t.parent?.kind === 'type' && included.has(t.parent.key)) base = ts(t.parent, 'out', new Set(t.genericParams))
    const abstract = t.abstract || t.kind === 'interface' ? 'abstract ' : ''
    const lines = [`${indent}${abstract}class ${name}${typeParams} extends ${base} {`, ...emitMembers(t, `${indent}  `), `${indent}}`]
    const nested = nestedOf.get(t.key) ?? []
    if (nested.length > 0) {
      lines.push(`${indent}namespace ${name} {`)
      for (const n of nested) lines.push(...emitType(n, `${indent}  `))
      lines.push(`${indent}}`)
    }
    return lines
  }

  const out: string[] = []
  out.push(`// Generated by frida-mono (Mono.dump) from: ${model.assemblies.join(', ')}${model.runtime === null ? '' : ` (Mono ${model.runtime})`}. Do not edit.`)
  out.push('/* eslint-disable */')
  out.push("import { EnumValue as $EnumValue, MonoObject as $MonoObject } from 'frida-mono'")
  out.push("import type { MArray as $MArray, MonoClassLike as $MonoClassLike, MonoEvent as $MonoEvent, MonoMethod as $MonoMethod, Ref as $Ref } from 'frida-mono'")
  out.push('')
  out.push(`declare namespace ${ROOT} {`)
  for (const [namespace, members] of [...byNamespace].sort(([a], [b]) => a.localeCompare(b))) {
    const indent = namespace === '' ? '  ' : '    '
    if (namespace !== '') out.push(`  namespace ${namespace} {`)
    for (const t of members) out.push(...emitType(t, indent))
    if (namespace !== '') out.push('  }')
  }
  out.push('}')
  out.push('')

  const roots = new Set<string>()
  for (const t of types) if (t.declaringType === null) roots.add(t.namespace === '' ? (tsNames.get(t.key) as string) : (t.namespace.split('.')[0] as string))
  out.push("declare module 'frida-mono' {")
  out.push('  interface MonoNamespaces {')
  for (const r of [...roots].sort()) out.push(`    ${r}: typeof ${ROOT}.${r}`)
  out.push('  }')
  out.push('  interface MonoTypes {')
  for (const t of types) out.push(`    ${JSON.stringify(t.key)}: typeof ${pathOf(t.key)}`)
  out.push('  }')
  out.push('}')
  out.push('')
  return out.join('\n')
}
