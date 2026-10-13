#!/usr/bin/env node
// Generates src/native/api.generated.ts, the typed table of Mono's public C API.
//
// Parses every `MONO_API` function declaration from the public headers of each runtime in
// test/e2e/runtimes.json and merges them: the newest runtime's signature wins, and entries that only
// some runtimes declare record which ones (for error messages). Headers are copied out of the Docker
// images into .cache/mono-headers/<runtime>/ once.
//
//   npm run gen:api

import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const runtimes = JSON.parse(readFileSync(join(root, 'test/e2e/runtimes.json'), 'utf8'))
const cacheDir = join(root, '.cache/mono-headers')
const outFile = join(root, 'src/native/api.generated.ts')

// ---------------------------------------------------------------------------------------------------
// Header extraction

function headersFor(runtime) {
  const dir = join(cacheDir, runtime.name)
  if (!existsSync(join(dir, 'mono'))) {
    console.log(`Extracting headers from ${runtime.image} …`)
    mkdirSync(dir, { recursive: true })
    const tar = execFileSync('docker', ['run', '--rm', runtime.image, 'tar', '-C', '/usr/include/mono-2.0', '-cf', '-', 'mono'], {
      maxBuffer: 1 << 28
    })
    execFileSync('tar', ['-C', dir, '-xf', '-'], { input: tar })
  }
  return dir
}

function listHeaders(dir) {
  const out = []
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry)
    if (statSync(path).isDirectory()) out.push(...listHeaders(path))
    else if (entry.endsWith('.h')) out.push(path)
  }
  return out.sort()
}

// ---------------------------------------------------------------------------------------------------
// Parsing

/** Removes comments and preprocessor lines, keeping both branches of every #if. */
function clean(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/\/\/.*$/gm, '')
    .replace(/\\\r?\n/g, ' ')
    .replace(/^\s*#.*$/gm, '')
    .replace(/\b(MONO_BEGIN_DECLS|MONO_END_DECLS|G_BEGIN_DECLS|G_END_DECLS)\b/g, '')
}

/** Splits into top-level statements. Brace blocks stay inside their statement (`typedef struct {…} X;`). */
function statements(source) {
  const out = []
  let depth = 0
  let current = ''
  for (const ch of source) {
    current += ch
    if (ch === '{') depth++
    else if (ch === '}') {
      depth--
      // A function body (`static inline … (…) { … }`) ends without a semicolon.
      if (depth === 0 && /\)\s*\{/.test(current) && !/^\s*typedef\b/.test(current)) {
        out.push(current)
        current = ''
      }
    } else if (ch === ';' && depth === 0) {
      out.push(current)
      current = ''
    }
  }
  return out.map((s) => s.replace(/\s+/g, ' ').trim()).filter((s) => s.length > 0)
}

const ATTRIBUTE_MACROS =
  /\b(MONO_RT_EXTERNAL_ONLY|MONO_RT_MANAGED_ATTR|MONO_RT_CENTRINEL_SUPPRESS|MONO_CONST_RETURN|MONO_EXTERN_C|MONO_BEGIN_DECLS|MONO_END_DECLS|G_BEGIN_DECLS|G_END_DECLS|_MONO_DEPRECATED|extern|const|volatile|struct|union|enum|__attribute__\s*\(\(.*?\)\))\b/g

function splitTopLevel(text, separator) {
  const parts = []
  let depth = 0
  let current = ''
  for (const ch of text) {
    if (ch === '(' || ch === '[') depth++
    else if (ch === ')' || ch === ']') depth--
    if (ch === separator && depth === 0) {
      parts.push(current.trim())
      current = ''
    } else current += ch
  }
  if (current.trim() !== '') parts.push(current.trim())
  return parts
}

/** `MonoClass *klass` → { type: 'MonoClass *', name: 'klass' }. */
function parseParam(text, index) {
  if (/\(\s*\*/.test(text)) {
    const name = /\(\s*\*\s*(\w+)?\s*\)/.exec(text)?.[1] ?? `arg${index}`
    return { type: '(*)()', name }
  }
  let t = text.replace(/\[[^\]]*\]/g, ' *').trim()
  const m = /^(.*?[\s*])(\w+)$/.exec(t)
  // A trailing identifier is the name unless it's part of the type (`unsigned int`, `MonoClass` alone).
  if (m && m[1].trim() !== '' && !/^(int|char|long|short|double|float|unsigned|signed)$/.test(m[2])) {
    return { type: m[1].trim(), name: m[2] }
  }
  return { type: t, name: `arg${index}` }
}

/** Parses one header. Fills `typedefs` (name → C type, '(*)()' for function pointers, 'enum', 'struct'). */
function parseHeader(source, typedefs) {
  const functions = []
  const text = clean(source)

  for (let s of statements(text)) {
    // Profiler callbacks are declared through an X-macro over profiler-events.h (see below).
    if (/^typedef\b/.test(s)) {
      s = s
        .replace(/\bMONO_RT_MANAGED_ATTR\b/g, '')
        .replace(/;$/, '')
        .trim()
      const fn = /\(\s*\*\s*(\w+)\s*\)\s*\(/.exec(s)
      if (fn) typedefs.set(fn[1], '(*)()')
      else if (/^typedef\s+enum\b/.test(s)) typedefs.set(/(\w+)\s*$/.exec(s)[1], 'enum')
      else if (/^typedef\s+(struct|union)\b.*\{/.test(s)) typedefs.set(/(\w+)\s*$/.exec(s)[1], 'struct')
      else {
        const m = /^typedef\s+(.*?)\s*(\w+)$/.exec(s)
        if (m) typedefs.set(m[2], m[1].includes('*') ? 'void *' : m[1].replace(/^(struct|union|enum)\s+\w+$/, '$1').replace('union', 'struct'))
      }
      continue
    }
    if (!/\bMONO_API\b|\bMONO_DEPRECATED\b/.test(s) || /\bMONO_API_DATA\b/.test(s)) continue
    if (s.includes('{')) s = s.slice(0, s.indexOf('{'))

    const deprecated = /\bMONO_DEPRECATED\b|\bMONO_RT_EXTERNAL_ONLY\b/.test(s) && /\bMONO_DEPRECATED\b/.test(s)
    const decl = s
      .replace(/\bMONO_DEPRECATED\b|\bMONO_API\b/g, ' ')
      .replace(ATTRIBUTE_MACROS, ' ')
      .replace(/;$/, '')
      .replace(/\s+/g, ' ')
      .trim()

    const m = /^(.*?)\b(\w+)\s*\((.*)\)$/.exec(decl)
    if (!m) {
      console.warn(`  skipped (unparsed): ${s}`)
      continue
    }
    const [, ret, name, paramText] = m
    if (ret.includes('(')) {
      console.warn(`  skipped (function pointer return): ${name}`)
      continue
    }
    const raw = splitTopLevel(paramText, ',')
    const variadic = raw.at(-1) === '...'
    const params = raw.filter((p) => p !== '...' && p !== 'void' && p !== '').map(parseParam)
    functions.push({ name, ret: ret.trim(), params, variadic, deprecated })
  }
  return functions
}

/** Expands profiler-events.h into its `mono_profiler_set_<name>_callback` declarations. */
function parseProfilerEvents(source) {
  const functions = []
  for (const m of clean(source).matchAll(/^\s*MONO_PROFILER_EVENT_\d\(\s*(\w+)\s*,/gm)) {
    functions.push({
      name: `mono_profiler_set_${m[1]}_callback`,
      ret: 'void',
      params: [
        { type: 'MonoProfilerHandle', name: 'handle' },
        { type: '(*)()', name: 'cb' }
      ],
      variadic: false,
      deprecated: false
    })
  }
  return functions
}

// ---------------------------------------------------------------------------------------------------
// Type mapping

const SCALARS = {
  void: 'void',
  char: 'char',
  gchar: 'char',
  'signed char': 'int8',
  'unsigned char': 'uint8',
  guint8: 'uint8',
  uint8_t: 'uint8',
  int8_t: 'int8',
  gint8: 'int8',
  short: 'int16',
  int16_t: 'int16',
  gint16: 'int16',
  'unsigned short': 'uint16',
  uint16_t: 'uint16',
  guint16: 'uint16',
  gunichar2: 'uint16',
  int: 'int',
  'signed int': 'int',
  int32_t: 'int',
  gint32: 'int',
  gint: 'int',
  gboolean: 'int',
  unsigned: 'uint',
  'unsigned int': 'uint',
  uint32_t: 'uint',
  guint32: 'uint',
  guint: 'uint',
  long: 'long',
  'unsigned long': 'ulong',
  'long long': 'int64',
  'unsigned long long': 'uint64',
  int64_t: 'int64',
  gint64: 'int64',
  uint64_t: 'uint64',
  guint64: 'uint64',
  size_t: 'size_t',
  uintptr_t: 'size_t',
  gsize: 'size_t',
  ssize_t: 'ssize_t',
  intptr_t: 'ssize_t',
  gssize: 'ssize_t',
  ptrdiff_t: 'ssize_t',
  float: 'float',
  double: 'double',
  wchar_t: 'uint16' // only mono_unichar2 on Windows; the non-Windows branch is uint16_t too
}

const unknownTypes = new Set()

/** C type → { native: Frida NativeType, ts: TypeScript type, brand?: struct name }. */
function mapType(cType, typedefs, seen = new Set()) {
  const type = cType
    .replace(/\s+/g, ' ')
    .replace(/\s*\*\s*/g, '*')
    .trim()
  if (type === '(*)()' || type === 'gpointer' || type === 'gconstpointer') return { native: 'pointer', ts: 'NativePointerValue' }
  if (type.includes('*')) {
    const base = type.replace(/\*/g, '').trim()
    const depth = (type.match(/\*/g) ?? []).length
    // One level of pointer to an opaque Mono struct gets a brand.
    if (depth === 1 && /^Mono\w+$/.test(base) && typedefs.get(base)?.startsWith('struct')) return { native: 'pointer', ts: 'pointer', brand: base }
    return { native: 'pointer', ts: 'pointer' }
  }
  if (type in SCALARS) return { native: SCALARS[type], ts: 'scalar' }
  const def = typedefs.get(type)
  if (def === 'enum' || def?.startsWith('enum ')) return { native: 'int', ts: 'scalar' }
  if (def === '(*)()') return { native: 'pointer', ts: 'NativePointerValue' }
  if (def !== undefined && !def.startsWith('struct') && !seen.has(type)) return mapType(def, typedefs, new Set([...seen, type]))
  unknownTypes.add(type)
  return { native: 'pointer', ts: 'pointer' }
}

const TS_SCALAR = {
  void: 'void',
  int64: 'Int64',
  uint64: 'UInt64',
  size_t: 'UInt64',
  ssize_t: 'Int64',
  pointer: 'NativePointer'
}

function tsReturn(t) {
  if (t.brand) return `${t.brand}Ptr`
  return TS_SCALAR[t.native] ?? 'number'
}

function tsParam(t) {
  if (t.brand) return `${t.brand}Ptr`
  if (t.ts === 'NativePointerValue' || t.native === 'pointer') return 'NativePointerValue'
  if (['int64', 'ssize_t'].includes(t.native)) return 'number | Int64'
  if (['uint64', 'size_t'].includes(t.native)) return 'number | UInt64'
  return 'number'
}

// ---------------------------------------------------------------------------------------------------
// Main

const JS_RESERVED = new Set(['function', 'default', 'class', 'new', 'delete', 'in', 'this', 'var', 'arguments', 'eval'])

// Oldest → newest, so later runtimes overwrite signatures.
const ordered = [...runtimes].sort((a, b) => a.version.localeCompare(b.version, undefined, { numeric: true }))
const merged = new Map()
const conflicts = []

for (const runtime of ordered) {
  const dir = headersFor(runtime)
  const typedefs = new Map()
  const decls = []
  for (const file of listHeaders(dir)) {
    const source = readFileSync(file, 'utf8')
    decls.push(...(file.endsWith('profiler-events.h') ? parseProfilerEvents(source) : parseHeader(source, typedefs)))
  }

  const names = new Set()
  for (const d of decls) {
    if (names.has(d.name)) continue
    names.add(d.name)
    const ret = mapType(d.ret, typedefs)
    const params = d.params.map((p) => ({ ...p, mapped: mapType(p.type, typedefs) }))
    const entry = {
      name: d.name,
      cDecl: `${d.ret} ${d.name} (${d.params.map((p) => (p.type === '(*)()' ? `<callback> ${p.name}` : `${p.type} ${p.name}`)).join(', ') || 'void'}${d.variadic ? ', ...' : ''})`
        .replace(/\s*(\*+)\s*/g, ' $1')
        .replace(/\s+/g, ' '),
      ret,
      params,
      variadic: d.variadic,
      deprecated: d.deprecated,
      runtimes: []
    }
    const previous = merged.get(d.name)
    if (previous) {
      const sig = (e) => [e.ret.native, ...e.params.map((p) => p.mapped.native), e.variadic].join(',')
      if (sig(previous) !== sig(entry)) conflicts.push(`${d.name}: ${previous.runtimes.at(-1)} (${sig(previous)}) → ${runtime.name} (${sig(entry)})`)
      entry.runtimes = previous.runtimes
    }
    entry.runtimes.push(runtime.name)
    merged.set(d.name, entry)
  }
  console.log(`${runtime.name}: ${names.size} functions`)
}

if (unknownTypes.size > 0) console.warn(`Unknown types (mapped to pointer): ${[...unknownTypes].sort().join(', ')}`)
if (conflicts.length > 0) console.warn(`Signature changes (newest wins):\n  ${conflicts.join('\n  ')}`)

const entries = [...merged.values()].sort((a, b) => a.name.localeCompare(b.name))
const allRuntimes = ordered.map((r) => r.name)
const brands = [
  ...new Set(
    entries
      .flatMap((e) => [e.ret, ...e.params.map((p) => p.mapped)])
      .map((t) => t.brand)
      .filter(Boolean)
  )
].sort()

const lines = []
lines.push(`// Generated by scripts/gen-api.mjs from the public headers of: ${allRuntimes.join(', ')}. Do not edit.`)
lines.push('// Regenerate with `npm run gen:api`.')
lines.push('')
lines.push("import type { ApiEntry } from './entry'")
lines.push('')
lines.push('declare const brand: unique symbol')
lines.push('/** A pointer to a specific Mono struct. Plain `NativePointer`s must be cast explicitly. */')
lines.push('export type Branded<Name extends string> = NativePointer & { readonly [brand]: Name }')
lines.push('')
for (const b of brands) lines.push(`export type ${b}Ptr = Branded<'${b}'>`)
lines.push('')
lines.push(`export const MONO_RUNTIMES_SCANNED = [${allRuntimes.map((r) => `'${r}'`).join(', ')}] as const`)
lines.push('')
lines.push('/** name → [return type, argument types, runtimes that declare it (omitted when all do), deprecated?] */')
lines.push('export const MONO_API_TABLE = {')
for (const e of entries) {
  const args = e.params.map((p) => `'${p.mapped.native}'`)
  if (e.variadic) args.push("'...'")
  const extra = []
  if (e.runtimes.length !== allRuntimes.length) extra.push(`runtimes: ${JSON.stringify(e.runtimes).replace(/"/g, "'")}`)
  if (e.deprecated) extra.push('deprecated: true')
  lines.push(`  ${e.name}: { ret: '${e.ret.native}', args: [${args.join(', ')}]${extra.length ? `, ${extra.join(', ')}` : ''} },`)
}
lines.push('} as const satisfies Record<string, ApiEntry>')
lines.push('')
lines.push('export type MonoApiName = keyof typeof MONO_API_TABLE')
lines.push('')
lines.push('/** Typed signatures of {@link MONO_API_TABLE}. */')
lines.push('export interface MonoApiFunctions {')
for (const e of entries) {
  const used = new Set()
  const params = e.params.map((p, i) => {
    let n = JS_RESERVED.has(p.name) ? `${p.name}_` : p.name
    if (used.has(n)) n = `${n}${i}`
    used.add(n)
    return `${n}: ${tsParam(p.mapped)}`
  })
  if (e.variadic) params.push('...rest: unknown[]')
  const notes = []
  if (e.runtimes.length !== allRuntimes.length) notes.push(`Only declared by: ${e.runtimes.join(', ')}.`)
  if (e.deprecated) notes.push('@deprecated')
  lines.push(`  /** \`${e.cDecl}\`${notes.length ? ` ${notes.join(' ')}` : ''} */`)
  lines.push(`  ${e.name}(${params.join(', ')}): ${tsReturn(e.ret)}`)
}
lines.push('}')
lines.push('')

writeFileSync(outFile, lines.join('\n'))
execFileSync('npx', ['prettier', '--write', outFile], { cwd: root, stdio: 'ignore' })
console.log(`Wrote ${relative(root, outFile)}: ${entries.length} functions, ${brands.length} branded pointer types`)
