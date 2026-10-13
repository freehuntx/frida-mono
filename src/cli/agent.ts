// Agent for `frida-mono dump` (cli/frida-mono.mjs); bundled to dist/cli-agent.js by `npm run build`.
import Mono from '../index'

interface DumpRequest {
  assemblies: string[] | null
  format: 'dts' | 'cs' | 'json'
  waitFor: string[] | null
}

rpc.exports = {
  async dump(request: DumpRequest) {
    const waitFor = request.waitFor ?? []
    return Mono.perform(() => Mono.dump({ format: request.format, ...(request.assemblies === null ? {} : { assemblies: request.assemblies }) }), { waitFor })
  }
}
