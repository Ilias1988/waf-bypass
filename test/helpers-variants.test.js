import test from 'node:test'
import assert from 'node:assert/strict'

import { detectTraversal, parseCommand, splitSqlKeywords } from '../src/utils/helpers.js'
import { finalizeVariants } from '../src/utils/variants.js'

test('command parser consumes complete encoded separators', () => {
  assert.deepEqual(parseCommand('%0aid'), { prefix: '%0a', command: 'id', args: '', raw: '%0aid' })
  assert.equal(parseCommand('; echo hello world').command, 'echo')
})

test('path parser supports Windows and POSIX traversal', () => {
  assert.equal(detectTraversal('..\\..\\Windows\\win.ini').depth, 2)
  assert.equal(detectTraversal('..\\..\\Windows\\win.ini').targetFile, 'Windows\\win.ini')
  assert.equal(detectTraversal('../../../etc/passwd').depth, 3)
  assert.equal(detectTraversal('../../../etc/passwd').targetFile, 'etc/passwd')
})

test('SQL keyword scanner never mutates quoted content or comments', () => {
  const input = "SELECT 'hex FROM' AS \"WHERE\" /* UNION */ FROM [SELECT] -- DELETE"
  const tokens = splitSqlKeywords(input)
  const keywords = tokens.filter((token) => token.type === 'keyword').map((token) => token.value.toUpperCase())
  assert.deepEqual(keywords, ['SELECT', 'AS', 'FROM'])
  assert.equal(tokens.map((token) => token.value).join(''), input)
})

test('variant finalizer keeps 12 bypasses and represents selected layers fairly', () => {
  const input = [{ payload: 'original', label: 'Original', layers: [] }]
  for (let index = 0; index < 20; index += 1) {
    input.push({ payload: `v${index}`, label: `v${index}`, layers: [`layer-${index % 6}`] })
  }
  const result = finalizeVariants(input, Array.from({ length: 6 }, (_, index) => `layer-${index}`))
  assert.equal(result.length, 13)
  const represented = new Set(result.flatMap((variant) => variant.layers))
  assert.deepEqual([...represented].sort(), Array.from({ length: 6 }, (_, index) => `layer-${index}`))
})

test('duplicate payloads merge their layer provenance', () => {
  const result = finalizeVariants([
    { payload: 'x', label: 'Original', layers: [] },
    { payload: 'y', label: 'A', layers: ['a'] },
    { payload: 'y', label: 'B', layers: ['b'] },
  ], ['a', 'b'])
  assert.deepEqual(result[1].layers.sort(), ['a', 'b'])
})
