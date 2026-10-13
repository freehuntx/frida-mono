/**
 * Overload resolution: picks the method whose parameters fit the JS arguments best.
 *
 * Every argument gets a score against each parameter; a candidate's score is the sum. `IMPOSSIBLE`
 * rules a candidate out. The best unique score wins; a tie is ambiguous. The rules follow C#'s
 * preferences loosely: exact > widening > boxing/conversion.
 */

export const IMPOSSIBLE = -Infinity

/** What a parameter accepts, precomputed from its `MonoType` once per method. */
export type ParamKind =
  | { kind: 'bool' }
  | { kind: 'char' }
  | { kind: 'integer'; name: IntegerName }
  | { kind: 'float' }
  | { kind: 'double' }
  | { kind: 'pointer' }
  | { kind: 'string' }
  | { kind: 'enum'; class: unknown }
  | { kind: 'struct'; class: unknown }
  | { kind: 'nullable'; inner: ParamKind }
  | { kind: 'array'; class: unknown }
  | { kind: 'reference'; class: unknown }
  | { kind: 'byref'; inner: ParamKind }
  /** A generic parameter (`T`) of an open method; accepts anything, inference decides. */
  | { kind: 'generic' }
  | { kind: 'unsupported' }

export type IntegerName = 'sbyte' | 'byte' | 'short' | 'ushort' | 'int' | 'uint' | 'long' | 'ulong'

// Literals, not `2n ** 63n`: BigInt `**` crashes Frida's QuickJS on Windows under Wine (eslint forbids it).
const INTEGER_RANGES: Record<IntegerName, [bigint, bigint]> = {
  sbyte: [-128n, 127n],
  byte: [0n, 255n],
  short: [-32768n, 32767n],
  ushort: [0n, 65535n],
  int: [-2147483648n, 2147483647n],
  uint: [0n, 4294967295n],
  long: [-9223372036854775808n, 9223372036854775807n],
  ulong: [0n, 18446744073709551615n]
}

/** Preference among integer parameter types for an integral JS number (C# picks `int` first, then wider). */
const INTEGER_PREFERENCE: Record<IntegerName, number> = { int: 10, long: 9, uint: 7, ulong: 6.5, short: 6, ushort: 5.5, sbyte: 5, byte: 5 }

/** How JS values are classified; implemented by the bridge (real classes) and by unit tests (fakes). */
export interface ArgumentInspector {
  /** The managed class of a wrapped object, struct or enum value; `undefined` for plain JS values. */
  classOf(value: unknown): unknown
  /** True for a bridge class (usable where `System.Type` is expected). */
  isClassWrapper(value: unknown): boolean
  isRef(value: unknown): value is { value: unknown }
  isEnumValue(value: unknown): boolean
  /** Inheritance distance from `from` up to `to` (0 = same class), or -1 if `from` isn't assignable to `to`. */
  distance(from: unknown, to: unknown): number
  /** True if `klass` is System.Type (or a base of it, like `object`, `MemberInfo`). */
  acceptsType(klass: unknown): boolean
  /** True if values of `klass` (a reference parameter type) can hold a boxed value or string. */
  acceptsBoxed(klass: unknown, boxed: 'string' | 'number' | 'boolean' | 'bigint'): boolean
  /** True if `klass` is a delegate type (a JS function converts to it). */
  isDelegate(klass: unknown): boolean
}

/** `instanceof NativePointer`, also safe in unit tests where Frida's globals don't exist. */
function isNativePointer(value: unknown): boolean {
  return typeof NativePointer !== 'undefined' && value instanceof NativePointer
}

function fitsInteger(value: number | bigint, name: IntegerName): boolean {
  const [min, max] = INTEGER_RANGES[name]
  const v = BigInt(value)
  return v >= min && v <= max
}

export function scoreArgument(value: unknown, param: ParamKind, inspect: ArgumentInspector): number {
  if (param.kind === 'byref') {
    if (!inspect.isRef(value)) return IMPOSSIBLE
    // `Mono.ref()` without a value fits any out parameter.
    return value.value === undefined ? 10 : Math.max(scoreArgument(value.value, param.inner, inspect), 1)
  }
  if (inspect.isRef(value)) return IMPOSSIBLE

  if (param.kind === 'generic') return 5
  if (param.kind === 'unsupported') return IMPOSSIBLE

  if (param.kind === 'nullable') {
    if (value === null || value === undefined) return 8
    const inner = scoreArgument(value, param.inner, inspect)
    return inner === IMPOSSIBLE ? IMPOSSIBLE : inner - 0.5
  }

  if (value === null || value === undefined) {
    return param.kind === 'reference' || param.kind === 'string' || param.kind === 'array' ? 5 : IMPOSSIBLE
  }

  switch (typeof value) {
    case 'number':
      if (Number.isInteger(value)) {
        if (param.kind === 'integer') return fitsInteger(value, param.name) ? INTEGER_PREFERENCE[param.name] : IMPOSSIBLE
        if (param.kind === 'double') return 8
        if (param.kind === 'float') return 7.5
        if (param.kind === 'enum') return 1
      } else {
        if (param.kind === 'double') return 10
        if (param.kind === 'float') return 8
      }
      if (param.kind === 'pointer') return 2
      if (param.kind === 'char') return IMPOSSIBLE
      return param.kind === 'reference' && inspect.acceptsBoxed(param.class, 'number') ? 2 : IMPOSSIBLE

    case 'bigint':
      if (param.kind === 'integer') return fitsInteger(value, param.name) ? (param.name === 'long' ? 10 : param.name === 'ulong' ? 9 : 4) : IMPOSSIBLE
      if (param.kind === 'double') return 3
      if (param.kind === 'pointer') return 2
      return param.kind === 'reference' && inspect.acceptsBoxed(param.class, 'bigint') ? 2 : IMPOSSIBLE

    case 'boolean':
      if (param.kind === 'bool') return 10
      return param.kind === 'reference' && inspect.acceptsBoxed(param.class, 'boolean') ? 2 : IMPOSSIBLE

    case 'string':
      if (param.kind === 'string') return 10
      if (param.kind === 'char') return value.length === 1 ? 8 : IMPOSSIBLE
      if (param.kind === 'enum') return 4
      return param.kind === 'reference' && inspect.acceptsBoxed(param.class, 'string') ? 5 : IMPOSSIBLE

    case 'function':
      if (inspect.isClassWrapper(value)) return param.kind === 'reference' && inspect.acceptsType(param.class) ? 9 : IMPOSSIBLE
      return param.kind === 'reference' && inspect.isDelegate(param.class) ? 8 : IMPOSSIBLE
  }

  if (isNativePointer(value)) {
    if (param.kind === 'pointer') return 10
    return param.kind === 'reference' || param.kind === 'string' || param.kind === 'array' ? 3 : IMPOSSIBLE
  }

  if (Array.isArray(value)) return param.kind === 'array' ? 8 : IMPOSSIBLE

  const klass = inspect.classOf(value)
  if (klass !== undefined) {
    if (param.kind === 'integer') return inspect.isEnumValue(value) ? 3 : IMPOSSIBLE
    if (param.kind !== 'enum' && param.kind !== 'struct' && param.kind !== 'reference' && param.kind !== 'array') return IMPOSSIBLE
    const d = inspect.distance(klass, param.class)
    if (d < 0) return IMPOSSIBLE
    // Value types reaching a reference parameter (object, ValueType, interfaces) get boxed.
    return Math.max(10 - d, param.kind === 'reference' ? 3 : 6)
  }

  // A plain JS object can stand in for a struct (fields by name).
  return param.kind === 'struct' ? 6 : IMPOSSIBLE
}

export interface Candidate<M> {
  method: M
  params: readonly ParamKind[]
}

export type Resolution<M> = { ok: true; method: M } | { ok: false; reason: 'none' | 'ambiguous'; candidates: M[] }

export function resolveOverload<M>(candidates: readonly Candidate<M>[], args: readonly unknown[], inspect: ArgumentInspector): Resolution<M> {
  let best: Candidate<M>[] = []
  let bestScore = IMPOSSIBLE
  for (const candidate of candidates) {
    if (candidate.params.length !== args.length) continue
    let score = 0
    for (let i = 0; i < args.length && score !== IMPOSSIBLE; i++) score += scoreArgument(args[i], candidate.params[i] as ParamKind, inspect)
    if (score === IMPOSSIBLE) continue
    if (score > bestScore) {
      bestScore = score
      best = [candidate]
    } else if (score === bestScore) best.push(candidate)
  }
  if (best.length === 1) return { ok: true, method: (best[0] as Candidate<M>).method }
  if (best.length > 1) return { ok: false, reason: 'ambiguous', candidates: best.map((c) => c.method) }
  return { ok: false, reason: 'none', candidates: candidates.map((c) => c.method) }
}
