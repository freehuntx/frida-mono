import { findMonoExport } from './exports'

let cached: string | null | undefined

/**
 * `mono_get_runtime_build_info()`, e.g. `"6.12.0.182 (tarball …)"`.
 * Returns `null` on runtimes that predate it, such as Unity's legacy `mono.dll`.
 */
export function getRuntimeBuildInfo(): string | null {
  if (cached !== undefined) return cached

  // Raw exports instead of `api`: the API's error messages call this.
  const getBuildInfo = findMonoExport('mono_get_runtime_build_info')
  if (getBuildInfo === null) return (cached = null)

  const info = new NativeFunction(getBuildInfo, 'pointer', [])() as NativePointer
  cached = info.readUtf8String()
  const free = findMonoExport('mono_free')
  if (free !== null) new NativeFunction(free, 'void', ['pointer'])(info)
  return cached
}
