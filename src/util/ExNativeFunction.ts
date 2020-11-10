/**
 * This is just to make it convinient to use NativeFunctions.
 * Otherwise we would have to store the informations somewhere else.
 * This way its attached to the NativeFunction. Awesome!
 */
interface ExNativeFunction extends NativePointer {
  (...args: NativeArgumentValue[]): any // eslint-disable-line @typescript-eslint/no-explicit-any
  apply(thisArg: NativePointerValue | null | undefined, args: NativeArgumentValue[]): any // eslint-disable-line @typescript-eslint/no-explicit-any
  call(thisArg?: NativePointerValue | null, ...args: NativeArgumentValue[]): any // eslint-disable-line @typescript-eslint/no-explicit-any
}

class ExNativeFunction extends NativeFunction {
  public address: NativePointerValue
  public retType: NativeType
  public argTypes: NativeType[]
  public abi: NativeABI = 'default'
  public options: NativeFunctionOptions

  constructor(address: NativePointerValue, retType: NativeType = 'void', argTypes: NativeType[] = [], abiOrOptions: NativeFunctionOptions | NativeABI = 'default') {
    super(address, retType, argTypes, abiOrOptions)

    this.address = address
    this.retType = retType
    this.argTypes = argTypes

    if (typeof abiOrOptions === 'string') {
      this.abi = abiOrOptions
    } else if (typeof abiOrOptions === 'object') {
      this.abi = abiOrOptions.abi || 'default'
      this.options = abiOrOptions
    }
  }

  nativeCallback(callback: NativeCallbackImplementation): NativeCallback {
    return new NativeCallback(callback, this.retType, this.argTypes, this.abi)
  }

  intercept(callbacksOrProbe: ScriptInvocationListenerCallbacks | NativeInvocationListenerCallbacks | InstructionProbeCallback, data?: NativePointerValue): InvocationListener {
    return Interceptor.attach(this.address, callbacksOrProbe, data)
  }

  replace(replacement: NativePointerValue, data?: NativePointerValue): void {
    return Interceptor.replace(this.address, replacement, data)
  }

  toString(): string {
    return `ExNativeFunction[address=${this.address}, retType=${this.retType}, argTypes=[${this.argTypes}], abi=${this.abi}]`
  }
}

export default ExNativeFunction
