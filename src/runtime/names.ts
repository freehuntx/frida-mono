/**
 * File names the Mono runtime ships under. Only used to try likely modules first;
 * the runtime is confirmed by its exports (it may also be linked into the main executable).
 */
export const KNOWN_MONO_MODULE_NAMES = [
  // Unity (MonoBleedingEdge / legacy)
  'mono-2.0-bdwgc.dll',
  'libmonobdwgc-2.0.so',
  'libmonobdwgc-2.0.dylib',
  'mono.dll',
  'libmono.so',
  'libmono.dylib',
  // Stock Mono / Xamarin
  'mono-2.0-sgen.dll',
  'libmonosgen-2.0.so',
  'libmonosgen-2.0.dylib',
  'mono-2.0.dll',
  'libmono-2.0.so',
  'libmono-2.0.dylib'
] as const

/** True for known runtime file names, ignoring case and ELF version suffixes (`libmonosgen-2.0.so.1.0.0`). */
export function isKnownMonoModuleName(name: string): boolean {
  const normalized = name.toLowerCase().replace(/(\.so)(\.\d+)+$/, '$1')
  return (KNOWN_MONO_MODULE_NAMES as readonly string[]).includes(normalized)
}
