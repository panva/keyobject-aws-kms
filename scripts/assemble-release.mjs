#!/usr/bin/env node
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'

import { assembleRelease } from './lib/npm-packaging.mjs'

const { values } = parseArgs({
  options: {
    artifacts: { type: 'string' },
    out: { type: 'string' },
    version: { type: 'string' },
  },
  strict: true,
})

if (!values.artifacts || !values.out || !values.version) {
  throw new Error(
    'usage: assemble-release.mjs --artifacts <directory> --out <directory> --version <version>',
  )
}

const result = assembleRelease({
  root: fileURLToPath(new URL('..', import.meta.url)),
  artifactsDirectory: values.artifacts,
  outputDirectory: values.out,
  version: values.version,
})

for (const file of result.files) console.log(file)
