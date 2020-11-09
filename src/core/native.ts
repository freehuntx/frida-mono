import module from './module'
import ExNativeFunction from '../util/ExNativeFunction'

export function createNativeFunction(name: string, retType: NativeType, argTypes: NativeType[], abiOrOptions: NativeFunctionOptions | NativeABI = 'default'): ExNativeFunction {
  const address = Module.findExportByName(module.name, name)

  if (!address) {
    console.warn('Warning! Native mono export not found! Expected export: ' + name)
    return null
  }

  return new ExNativeFunction(address, retType, argTypes, abiOrOptions)
}
