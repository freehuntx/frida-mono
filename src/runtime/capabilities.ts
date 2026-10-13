import { monoExports } from './exports'

/**
 * What the loaded runtime supports, derived from its exports. Features choose their
 * implementation from these flags rather than from version strings, which Unity's forks misreport.
 */
export interface Capabilities {
  /** `mono_method_get_unmanaged_thunk`: fast calls without `mono_runtime_invoke`. */
  readonly unmanagedThunk: boolean
  /** New profiler API (`mono_profiler_create`, Mono ≥ 5.6). */
  readonly newProfiler: boolean
  /** Legacy profiler API (`mono_profiler_install`). */
  readonly legacyProfiler: boolean
  /** `mono_image_get_table_rows`; otherwise `mono_image_get_table_info` + `mono_table_info_get_rows`. */
  readonly imageTableRows: boolean
  /** `mono_assembly_name_get_name` and friends. */
  readonly assemblyNameAccessors: boolean
  /** `mono_get_runtime_build_info`. */
  readonly buildInfo: boolean
  /** Unity's fork additions (`mono_unity_*`). */
  readonly unityExtensions: boolean
}

let cached: Capabilities | null = null

export function getCapabilities(): Capabilities {
  if (cached !== null) return cached
  const exports = monoExports()
  const has = (name: string): boolean => exports.has(name)
  return (cached = Object.freeze({
    unmanagedThunk: has('mono_method_get_unmanaged_thunk'),
    newProfiler: has('mono_profiler_create'),
    legacyProfiler: has('mono_profiler_install'),
    imageTableRows: has('mono_image_get_table_rows'),
    assemblyNameAccessors: has('mono_assembly_name_get_name'),
    buildInfo: has('mono_get_runtime_build_info'),
    unityExtensions: [...exports.keys()].some((name) => name.startsWith('mono_unity_'))
  }))
}
