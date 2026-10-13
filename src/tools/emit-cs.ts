import type { DumpModel, MethodModel, TypeModel, TypeRef } from './model'

/** A C#-like listing of a {@link DumpModel}, for reading. Not meant to compile. */
export function emitCs(model: DumpModel): string {
  const name = (ref: TypeRef): string => {
    switch (ref.kind) {
      case 'void':
        return 'void'
      case 'primitive':
        return ref.name === 'type' ? 'System.Type' : ref.name === 'nint' ? 'IntPtr' : ref.name === 'nuint' ? 'UIntPtr' : ref.name
      case 'generic':
        return ref.name
      case 'byref':
        return `ref ${name(ref.type)}`
      case 'array':
        return `${name(ref.element)}[${','.repeat(ref.rank - 1)}]`
      case 'pointer':
        return 'void*'
      case 'nullable':
        return `${name(ref.type)}?`
      case 'type': {
        const base = ref.key.replace(/`\d+$/, '').replace(/\+/g, '.')
        return ref.args.length > 0 ? `${base}<${ref.args.map(name).join(', ')}>` : base
      }
    }
  }

  const method = (m: MethodModel, typeName: string | null): string => {
    const modifiers = [m.access, m.static ? 'static' : '', m.abstract ? 'abstract' : m.virtual ? 'virtual' : ''].filter(Boolean).join(' ')
    const generic = m.genericParams.length > 0 ? `<${m.genericParams.join(', ')}>` : ''
    const params = m.params.map((p) => `${p.out ? 'out ' + name(p.type).replace(/^ref /, '') : name(p.type)} ${p.name}`).join(', ')
    return typeName === null ? `${modifiers} ${name(m.returns)} ${m.name}${generic}(${params});` : `${modifiers} ${typeName}(${params});`
  }

  const nestedOf = new Map<string, TypeModel[]>()
  for (const t of model.types) if (t.declaringType !== null) nestedOf.set(t.declaringType, [...(nestedOf.get(t.declaringType) ?? []), t])

  const emitType = (t: TypeModel, indent: string): string[] => {
    const generic = t.genericParams.length > 0 ? `<${t.genericParams.join(', ')}>` : ''
    const bases = [...(t.parent !== null && t.parent.kind === 'type' && t.parent.key !== 'System.Object' ? [t.parent] : []), ...t.interfaces].map(name)
    const keyword = t.kind === 'struct' ? 'struct' : t.kind === 'enum' ? 'enum' : t.kind === 'interface' ? 'interface' : t.kind === 'delegate' ? 'delegate class' : 'class'
    const modifiers = [
      t.access === 'nested' ? '' : t.access,
      t.kind === 'class' && t.abstract && t.sealed ? 'static' : t.kind === 'class' && t.abstract ? 'abstract' : t.kind === 'class' && t.sealed ? 'sealed' : ''
    ]
      .filter(Boolean)
      .join(' ')
    const lines = [`${indent}${modifiers ? `${modifiers} ` : ''}${keyword} ${t.name}${generic}${bases.length > 0 ? ` : ${bases.join(', ')}` : ''}`, `${indent}{`]
    const inner = `${indent}    `
    if (t.kind === 'enum') for (const v of t.enumValues) lines.push(`${inner}${v.name} = ${v.value},`)
    for (const f of t.fields) lines.push(`${inner}${f.access}${f.literal ? ' const' : f.static ? ' static' : ''}${f.readonly ? ' readonly' : ''} ${name(f.type)} ${f.name};`)
    for (const p of t.properties) {
      const accessors = `{ ${p.get ? 'get; ' : ''}${p.set ? 'set; ' : ''}}`
      const label = p.index.length > 0 ? `this[${p.index.map(name).join(', ')}]` : p.name
      lines.push(`${inner}${p.static ? 'static ' : ''}${name(p.type)} ${label} ${accessors}`)
    }
    for (const e of t.events) lines.push(`${inner}${e.static ? 'static ' : ''}event ${e.type === null ? '?' : name(e.type)} ${e.name};`)
    for (const c of t.constructors) lines.push(`${inner}${method(c, t.name)}`)
    for (const m of t.methods) lines.push(`${inner}${method(m, null)}`)
    for (const n of nestedOf.get(t.key) ?? []) lines.push('', ...emitType(n, inner))
    lines.push(`${indent}}`)
    return lines
  }

  const out = [`// ${model.assemblies.join(', ')}${model.runtime === null ? '' : ` — Mono ${model.runtime}`}`, '']
  const byNamespace = new Map<string, TypeModel[]>()
  for (const t of model.types) if (t.declaringType === null) byNamespace.set(t.namespace, [...(byNamespace.get(t.namespace) ?? []), t])
  for (const [namespace, types] of byNamespace) {
    const indent = namespace === '' ? '' : '    '
    if (namespace !== '') out.push(`namespace ${namespace}`, '{')
    for (const t of types) out.push(...emitType(t, indent), '')
    if (namespace !== '') out.push('}', '')
  }
  return out.join('\n')
}
