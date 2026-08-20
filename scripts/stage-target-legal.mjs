#!/usr/bin/env node
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'

import { stageTargetLegalPayload } from './lib/npm-packaging.mjs'

const { values } = parseArgs({
  options: {
    out: { type: 'string' },
    target: { type: 'string' },
  },
  strict: true,
})

if (!values.out || !values.target) {
  throw new Error('usage: stage-target-legal.mjs --target <target> --out <directory>')
}

stageTargetLegalPayload({
  root: fileURLToPath(new URL('..', import.meta.url)),
  destination: values.out,
  targetName: values.target,
})
