/**
 * This is just to make it convinient to use NativeFunctions.
 * Otherwise we would have to store the informations somewhere else.
 * This way its attached to the NativeFunction. Awesome!
 */
/*function ExNativeFunction(address: NativePointerValue, retType: NativeType, argTypes: NativeType[], abiOrOptions: NativeFunctionOptions | NativeABI): void {
  const nativeFunction = new NativeFunction(address, retType, argTypes, abiOrOptions)
  let abi: NativeABI = 'default'
  let options: NativeFunctionOptions = undefined

  if (typeof abiOrOptions === 'string') {
    abi = abiOrOptions
  }
  else if(typeof abiOrOptions === 'object') {
    abi = abiOrOptions.abi || 'default'
    options = abiOrOptions
  }

  Object.assign(nativeFunction, {
    address,
    retType,
    argTypes,
    abi,
    options,

    nativeCallback(callback): NativeCallback {
      return new NativeCallback(callback, this.retType, this.argTypes, this.abi)
    },
    intercept(callbacksOrProbe: ScriptInvocationListenerCallbacks | NativeInvocationListenerCallbacks | InstructionProbeCallback, data?: NativePointerValue) {
      return Interceptor.attach(this.address, callbacksOrProbe, data)
    },
    replace(replacement: NativePointerValue, data?: NativePointerValue) {
      return Interceptor.replace(this.address, replacement, data)
    }
  })

  // These typecasts are just to please typescript.  Otherwise we couldnt invoke this with new while returning a different object.
  return (nativeFunction as unknown) as void
}*/

class ExNativeFunction extends Function {
  public address: NativePointerValue
  public retType: NativeType
  public argTypes: NativeType[]
  public abi: NativeABI = 'default'
  public options: NativeFunctionOptions

  constructor(address: NativePointerValue, retType: NativeType = 'void', argTypes: NativeType[] = [], abiOrOptions: NativeFunctionOptions | NativeABI = 'default') {
    super()
    const native = new NativeFunction(address, retType, argTypes, abiOrOptions)

    this.address = address
    this.retType = retType
    this.argTypes = argTypes

    if (typeof abiOrOptions === 'string') {
      this.abi = abiOrOptions
    } else if (typeof abiOrOptions === 'object') {
      this.abi = abiOrOptions.abi || 'default'
      this.options = abiOrOptions
    }

    ;(<any>Object).assign(native, this)

    return (native as unknown) as ExNativeFunction
  }

  nativeCallback(callback): NativeCallback {
    return new NativeCallback(callback, this.retType, this.argTypes, this.abi)
  }

  intercept(callbacksOrProbe: ScriptInvocationListenerCallbacks | NativeInvocationListenerCallbacks | InstructionProbeCallback, data?: NativePointerValue) {
    return Interceptor.attach(this.address, callbacksOrProbe, data)
  }

  replace(replacement: NativePointerValue, data?: NativePointerValue) {
    return Interceptor.replace(this.address, replacement, data)
  }
}

export default ExNativeFunction
