export interface ParsedClassName {
  namespace: string
  /** The outer class name, then one entry per nesting level. */
  names: [string, ...string[]]
}

/** Splits `Ns.Outer+Inner` / `Ns.Outer/Inner` into namespace and nesting path. */
export function parseClassName(fullName: string): ParsedClassName {
  const [outer = '', ...nested] = fullName.split(/[+/]/)
  const dot = outer.lastIndexOf('.')
  return { namespace: dot === -1 ? '' : outer.slice(0, dot), names: [outer.slice(dot + 1), ...nested] }
}
