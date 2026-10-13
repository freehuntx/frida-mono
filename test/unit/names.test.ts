import { describe, expect, it } from 'vitest'
import { isKnownMonoModuleName } from '../../src/runtime/names'

describe('isKnownMonoModuleName', () => {
  it.each(['mono-2.0-bdwgc.dll', 'MONO.DLL', 'libmonosgen-2.0.so', 'libmonosgen-2.0.so.1.0.0', 'libmonobdwgc-2.0.dylib'])('accepts %s', (name) => {
    expect(isKnownMonoModuleName(name)).toBe(true)
  })

  it.each(['libmono-native.so', 'libmono-btls-shared.so', 'mono-sgen', 'UnityPlayer.dll', 'libmonosgen-2.0.so.bak'])('rejects %s', (name) => {
    expect(isKnownMonoModuleName(name)).toBe(false)
  })
})
