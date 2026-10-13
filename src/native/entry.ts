/** One row of the generated C API table. */
export interface ApiEntry {
  readonly ret: NativeFunctionReturnType
  readonly args: readonly (NativeFunctionArgumentType | '...')[]
  /** Runtimes whose headers declare the function; omitted when every scanned runtime does. */
  readonly runtimes?: readonly string[]
  readonly deprecated?: boolean
}
