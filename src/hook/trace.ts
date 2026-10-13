import { MonoError } from '../errors'
import { assemblies } from '../meta/lookup'
import { api } from '../native/api'
import { Method } from '../meta/method'
import { callOriginal, override } from './hooks'
import { unsupportedReason } from './native'

function globToRegExp(glob: string): RegExp {
  return new RegExp(
    `^${glob
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.')}$`
  )
}

/** Methods matching `'Class:Method'` globs (`*`, `?`) on full class names, e.g. `'Game.*Player*:Take*'`. */
export function findMethods(pattern: string): Method[] {
  const [classGlob, methodGlob = '*'] = pattern.split(':')
  if (classGlob === undefined || classGlob === '') throw new MonoError(`Invalid pattern ${pattern}: expected 'Class:Method'`)
  const classRe = globToRegExp(classGlob)
  const methodRe = globToRegExp(methodGlob)
  return assemblies()
    .flatMap((a) => a.image.classes)
    .filter((c) => classRe.test(c.fullName))
    .flatMap((c) => c.methods.filter((m) => methodRe.test(m.name)))
}

function describe(value: unknown): string {
  if (typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'bigint') return `${value}n`
  try {
    return String(value)
  } catch {
    return Object.prototype.toString.call(value)
  }
}

const depth = new Map<ThreadId, number>()

/**
 * Logs calls (with arguments and return values, indented by call depth) of every method matching
 * `pattern` (see {@link findMethods}). Methods that can't be hooked are skipped. Returns a function
 * that stops tracing.
 */
export function trace(pattern: string, log: (line: string) => void = (line) => console.log(line)): () => void {
  const removers: (() => void)[] = []
  let skipped = 0
  for (const method of findMethods(pattern)) {
    if (unsupportedReason(method) !== null) {
      skipped++
      continue
    }
    const name = `${method.class.fullName}.${method.name}`
    removers.push(
      override(method, (self, args) => {
        const thread = Process.getCurrentThreadId()
        const level = depth.get(thread) ?? 0
        const indent = '  '.repeat(level)
        log(`${indent}→ ${name}(${args.map(describe).join(', ')})`)
        depth.set(thread, level + 1)
        try {
          const result = callOriginal(method, self, args)
          log(`${indent}← ${name} = ${method.returnType.isVoid ? 'void' : describe(result)}`)
          return result
        } finally {
          depth.set(thread, level)
        }
      })
    )
  }
  log(`frida-mono: tracing ${removers.length} method(s) matching ${pattern}${skipped > 0 ? ` (${skipped} skipped: not hookable)` : ''}`)
  return () => removers.forEach((remove) => remove())
}

/** The managed method containing a native code address, as `Ns.Class:Method (args) + 0x12`, or `null`. */
export function symbolicate(address: NativePointer): string | null {
  const info = api.mono_jit_info_table_find(api.mono_domain_get(), address)
  if (info.isNull()) return null
  const method = Method.from(api.mono_jit_info_get_method(info))
  return `${method.fullName} + 0x${address.sub(api.mono_jit_info_get_code_start(info)).toString(16)}`
}
