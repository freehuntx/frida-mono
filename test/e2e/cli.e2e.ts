import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { beforeAll, describe, expect, it } from 'vitest'
import { currentRuntime } from './support/runtime'

const runtime = currentRuntime()

// The CLI detaches when it's done, which crashes targets on old glibc (mono-4.8, unity-legacy).
describe.skipIf(runtime.detachCrashes === true)('cli', () => {
  beforeAll(() => {
    const build = spawnSync('node', ['scripts/build-cli-agent.mjs'], { encoding: 'utf8' })
    expect(build.status, build.stderr).toBe(0)
  }, 120_000)

  it('dumps typings of a running process to a file', () => {
    const out = '.cache/cli/TestLib.d.ts'
    const cli = spawnSync('node', ['cli/frida-mono.mjs', 'dump', '-n', runtime.process ?? 'mono', '-a', 'TestLib', '-o', out], { encoding: 'utf8' })
    expect(cli.status, cli.stderr).toBe(0)
    expect(cli.stderr).toContain(`wrote ${out}`)
    const dts = readFileSync(out, 'utf8')
    expect(dts).toContain("declare module 'frida-mono'")
    expect(dts).toContain('class Dog extends __mono.FridaMono.Tests.Animal')
  }, 120_000)

  it('prints a C# listing to stdout', () => {
    const cli = spawnSync('node', ['cli/frida-mono.mjs', 'dump', '-n', runtime.process ?? 'mono', '-a', 'TestLib', '--format', 'cs'], { encoding: 'utf8' })
    expect(cli.status, cli.stderr).toBe(0)
    expect(cli.stdout).toContain('public static string Pick(int x);')
  }, 120_000)

  it('explains bad usage', () => {
    const cli = spawnSync('node', ['cli/frida-mono.mjs', 'dump'], { encoding: 'utf8' })
    expect(cli.status).toBe(2)
    expect(cli.stderr).toContain('give exactly one of --name or --pid')
  })
})
