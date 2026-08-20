#!/usr/bin/env node
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'

import { packBuildPackages } from './lib/npm-packaging.mjs'

const { values } = parseArgs({
  options: {
    'build-dir': { type: 'string' },
    out: { type: 'string' },
    target: { type: 'string' },
  },
  strict: true,
})

if (!values['build-dir'] || !values.out || !values.target) {
  throw new Error('usage: pack-npm.mjs --build-dir <directory> --target <target> --out <directory>')
}

const result = packBuildPackages({
  root: fileURLToPath(new URL('..', import.meta.url)),
  buildDirectory: values['build-dir'],
  outputDirectory: values.out,
  targetName: values.target,
})

console.log(result.satelliteTarball)
console.log(result.coreTarball)
