import { collect, type DumpOptions } from './collect'
import { emitCs } from './emit-cs'
import { emitDts } from './emit-dts'
import type { DumpModel } from './model'

export interface DumpFormatOptions extends DumpOptions {
  /** `dts` (typings for the bridge), `cs` (C#-like listing) or `json` (the model). Default `dts`. */
  format?: 'dts' | 'cs' | 'json'
}

/**
 * Dumps the types of loaded assemblies: `Mono.dump({ assemblies: ['Assembly-CSharp'] })`.
 * By default every non-framework assembly, as TypeScript typings.
 */
export function dump(options: DumpFormatOptions & { format: 'json' }): DumpModel
export function dump(options?: DumpFormatOptions): string
export function dump(options: DumpFormatOptions = {}): string | DumpModel {
  const model = collect(options)
  switch (options.format ?? 'dts') {
    case 'json':
      return model
    case 'cs':
      return emitCs(model)
    default:
      return emitDts(model)
  }
}
