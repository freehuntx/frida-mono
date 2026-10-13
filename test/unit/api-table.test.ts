import { describe, expect, it } from 'vitest'
import { MONO_API_TABLE, MONO_RUNTIMES_SCANNED } from '../../src/native/api.generated'

const table: Record<string, { ret: string; args: readonly string[]; runtimes?: readonly string[] }> = MONO_API_TABLE

describe('generated Mono API table', () => {
  it('covers the public API of every scanned runtime', () => {
    expect(MONO_RUNTIMES_SCANNED.length).toBeGreaterThanOrEqual(3)
    expect(Object.keys(table).length).toBeGreaterThan(700)
  })

  it.each([
    ['mono_thread_attach', 'pointer', ['pointer']],
    ['mono_runtime_invoke', 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
    ['mono_gchandle_new', 'uint', ['pointer', 'int']],
    ['mono_string_new_utf16', 'pointer', ['pointer', 'pointer', 'int']],
    ['mono_array_addr_with_size', 'pointer', ['pointer', 'int', 'size_t']],
    ['mono_class_get_type_token', 'uint', ['pointer']],
    ['mono_trace_set_level_string', 'void', ['pointer']]
  ])('maps %s', (name, ret, args) => {
    expect(table[name]).toMatchObject({ ret, args })
  })

  it('records functions only some runtimes declare', () => {
    expect(table.mono_profiler_install?.runtimes).toEqual(['mono-4.8'])
    expect(table.mono_profiler_create?.runtimes).toEqual(['mono-5.20', 'mono-6.12'])
    expect(table.mono_thread_attach?.runtimes).toBeUndefined()
  })

  it('expands the profiler callback setters from profiler-events.h', () => {
    expect(table.mono_profiler_set_jit_done_callback).toMatchObject({ ret: 'void', args: ['pointer', 'pointer'] })
  })
})
