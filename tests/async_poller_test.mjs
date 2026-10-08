import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import ts from '../frontend/node_modules/typescript/lib/typescript.js'

const source = readFileSync(new URL('../frontend/src/lib/asyncPoller.ts', import.meta.url), 'utf8')
const js = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { createAsyncPoller } = await import('data:text/javascript;base64,' + Buffer.from(js).toString('base64'))
const flush = async () => { for (let i = 0; i < 4; i++) await Promise.resolve() }

async function scenario(body) {
  const realSet = globalThis.setTimeout, realClear = globalThis.clearTimeout
  let now = 0, nextId = 0
  const timers = new Map()
  const calls = [], applied = []
  globalThis.setTimeout = (callback, delay) => {
    const id = ++nextId; timers.set(id, { due: now + delay, callback }); return id
  }
  globalThis.clearTimeout = id => timers.delete(id)
  const poller = createAsyncPoller(100, signal => new Promise((resolve, reject) => {
    calls.push({ signal, resolve, reject })
  }), data => applied.push(data))
  const tick = ms => {
    const end = now + ms
    while (true) {
      const ready = [...timers].filter(([, t]) => t.due <= end).sort((a, b) => a[1].due - b[1].due)[0]
      if (!ready) break
      timers.delete(ready[0]); now = ready[1].due; ready[1].callback()
    }
    now = end
  }
  try { await body({ poller, calls, applied, tick, timers }) }
  finally { poller.stop(); globalThis.setTimeout = realSet; globalThis.clearTimeout = realClear }
}

test('slow requests never accumulate and start is idempotent', () => scenario(async ({ poller, calls, tick, applied }) => {
  poller.start(); poller.start(); tick(1000)
  assert.equal(calls.length, 1)
  calls[0].resolve('one'); await flush(); assert.deepEqual(applied, ['one'])
  tick(99); assert.equal(calls.length, 1)
  tick(1); assert.equal(calls.length, 2)
}))
test('selection refresh aborts old request and ignores out-of-order results', () => scenario(async ({ poller, calls, applied, tick }) => {
  poller.start(); poller.refresh(); assert.equal(calls[0].signal.aborted, true)
  calls[1].resolve('new PID'); await flush()
  calls[0].resolve('old PID'); await flush()
  assert.deepEqual(applied, ['new PID'])
  tick(100); assert.equal(calls.length, 3)
}))
test('hidden/unmounted view cancels requests and rejects late writes', () => scenario(async ({ poller, calls, applied, tick, timers }) => {
  poller.start(); poller.stop(); assert.equal(calls[0].signal.aborted, true)
  calls[0].resolve('late'); await flush(); tick(1000)
  assert.deepEqual(applied, []); assert.equal(calls.length, 1); assert.equal(timers.size, 0)
  poller.refresh(); assert.equal(calls.length, 1)
  poller.start(); assert.equal(calls.length, 2)
  calls[1].resolve('visible'); await flush(); assert.deepEqual(applied, ['visible'])
}))
test('backend errors retry without creating duplicate timers', () => scenario(async ({ poller, calls, applied, tick }) => {
  poller.start(); calls[0].reject(new Error('offline')); await flush()
  tick(100); assert.equal(calls.length, 2)
  calls[1].resolve('recovered'); await flush(); assert.deepEqual(applied, ['recovered'])
}))
test('stop during the wait cancels the next refresh', () => scenario(async ({ poller, calls, tick }) => {
  poller.start(); calls[0].resolve('ok'); await flush()
  poller.stop(); tick(1000); assert.equal(calls.length, 1)
}))
