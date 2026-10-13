import { getMonoModule, getRuntimeBuildInfo, monoExports } from '../../../src'

rpc.exports = {
  info() {
    return { module: getMonoModule().name, buildInfo: getRuntimeBuildInfo(), exportCount: monoExports().size }
  }
}
