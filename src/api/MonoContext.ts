import { createNativeFunction } from 'core/native'
import { MonoBase } from './MonoBase'

export const mono_context_get = createNativeFunction('mono_context_get', 'pointer', [])
export const mono_context_set = createNativeFunction('mono_context_set', 'void', ['pointer'])
export const mono_context_get_domain_id = createNativeFunction('mono_context_get_domain_id', 'int32', ['pointer'])
export const mono_context_get_id = createNativeFunction('mono_context_get_id', 'int32', ['pointer'])

export class MonoContext extends MonoBase {
  /**
   * Context IDs are guaranteed to be unique for the duration of a Mono process; they are never reused.
   * @returns {number} The unique ID for context.
   */
  get id(): number {
    return mono_context_get_id(this.$address)
  }

  /**
   * @returns {number} The ID of the domain that context was created in.
   */
  get domainId(): number {
    return mono_context_get_domain_id(this.$address)
  }

  /**
   */
  set(): void {
    mono_context_set(this.$address)
  }

  /**
   * @returns {MonoContext} the current Mono Application Context.
   */
  static get(): MonoContext {
    return MonoContext.fromAddress(mono_context_get())
  }
}
