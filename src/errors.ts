/** Base class of every error thrown by frida-mono. */
export class MonoError extends Error {
  override name = 'MonoError'
}

/** Mono isn't loaded in the process, or isn't initialized yet. */
export class MonoNotFoundError extends MonoError {
  override name = 'MonoNotFoundError'
}

/** A C API function was called that the loaded runtime doesn't export. */
export class MonoApiMissingError extends MonoError {
  override name = 'MonoApiMissingError'

  constructor(
    readonly functionName: string,
    message: string
  ) {
    super(message)
  }
}
