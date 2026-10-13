#!/usr/bin/env node
// Builds the Docker images for Unity's Mono forks used by the e2e matrix.
//
//   node scripts/build-unity-images.mjs            # both
//   node scripts/build-unity-images.mjs mbe        # MonoBleedingEdge (≈ 30-60 min)
//   node scripts/build-unity-images.mjs legacy     # legacy Mono 2.6 (≈ 5 min)
//
// With UNITY_IMAGE_CACHE=gha (CI), layers are cached in the GitHub Actions cache through buildx,
// so the MonoBleedingEdge build only runs when its Dockerfile changes.

import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const docker = join(root, 'docker')
const LEGACY = { branch: 'unity-2018.4', commit: 'e20cf158facacfe732f4b53c0501e7263e114efd' }

function run(command, args, options = {}) {
  console.log(`$ ${command} ${args.join(' ')}`)
  execFileSync(command, args, { stdio: 'inherit', ...options })
}

function dockerBuild(name) {
  const cache = process.env.UNITY_IMAGE_CACHE === 'gha' ? ['--cache-from', `type=gha,scope=${name}`, '--cache-to', `type=gha,mode=max,scope=${name}`] : []
  run('docker', ['buildx', 'build', '--load', ...cache, '-f', join(docker, `${name}.Dockerfile`), '-t', `frida-mono/${name}`, docker])
}

function buildMbe() {
  dockerBuild('unity-mbe')
}

function buildLegacy() {
  // Squeeze can't talk to GitHub anymore, so the source goes in as a tarball.
  const source = join(root, '.cache/unity-src/legacy')
  if (!existsSync(source)) {
    mkdirSync(dirname(source), { recursive: true })
    run('git', ['clone', '--depth', '1', '-b', LEGACY.branch, 'https://github.com/Unity-Technologies/mono.git', source])
  }
  run('git', ['-C', source, 'fetch', '--depth', '1', 'origin', LEGACY.commit])
  run('git', ['-C', source, 'archive', '--format=tar.gz', '-o', join(docker, 'legacy-src.tar.gz'), LEGACY.commit])
  dockerBuild('unity-legacy')
}

const which = process.argv.slice(2)
if (which.length === 0 || which.includes('legacy')) buildLegacy()
if (which.length === 0 || which.includes('mbe')) buildMbe()
