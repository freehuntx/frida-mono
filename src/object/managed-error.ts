import { MonoError } from '../errors'
import type { MonoObjectPtr } from '../native/api.generated'
import { objectToString, ManagedObject } from './object'

/** A managed exception thrown by a call. `managed` is the exception object, `managedStack` its `ToString()`. */
export class ManagedError extends MonoError {
  override name = 'ManagedError'
  readonly managed: ManagedObject
  /** Full name of the exception class, e.g. `System.InvalidOperationException`. */
  readonly type: string
  /** `Exception.ToString()`: type, message and managed stack trace. */
  readonly managedStack: string

  constructor(exception: MonoObjectPtr) {
    const managed = new ManagedObject(exception)
    const text = objectToString(exception) ?? managed.class.fullName
    // ToString() starts with "Type: Message"; keep only that first line as the JS message.
    super(text.split('\n', 1)[0] ?? text)
    this.managed = managed
    this.type = managed.class.fullName
    this.managedStack = text
  }
}
