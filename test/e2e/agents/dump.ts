import Mono from '../../../src'

rpc.exports = {
  dump(format: 'dts' | 'cs' | 'json', assemblies?: string[] | null) {
    // RPC passes omitted arguments as null.
    return Mono.performNow(() => Mono.dump({ assemblies: assemblies ?? ['TestLib'], format }))
  }
}
