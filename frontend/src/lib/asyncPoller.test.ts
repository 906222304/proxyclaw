import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createAsyncPoller } from './asyncPoller'

type Call = { signal: AbortSignal; resolve: (v: string) => void; reject: (e: Error) => void }

const flush = async () => {
  for (let i = 0; i < 4; i++) await Promise.resolve()
}

describe('createAsyncPoller', () => {
  let calls: Call[]
  let applied: string[]
  let poller: ReturnType<typeof createAsyncPoller<string>>

  beforeEach(() => {
    vi.useFakeTimers()
    calls = []
    applied = []
    poller = createAsyncPoller<string>(
      100,
      (signal) => new Promise<string>((resolve, reject) => { calls.push({ signal, resolve, reject }) }),
      (data) => { applied.push(data) },
    )
  })

  afterEach(() => {
    poller.stop()
    vi.useRealTimers()
  })

  it('never accumulates slow requests and start is idempotent', async () => {
    poller.start(); poller.start(); vi.advanceTimersByTime(1000)
    expect(calls).toHaveLength(1)
    calls[0]!.resolve('one'); await flush(); expect(applied).toEqual(['one'])
    vi.advanceTimersByTime(99); expect(calls).toHaveLength(1)
    vi.advanceTimersByTime(1); expect(calls).toHaveLength(2)
  })

  it('refresh aborts the old request and ignores out-of-order results', async () => {
    poller.start(); poller.refresh(); expect(calls[0]!.signal.aborted).toBe(true)
    calls[1]!.resolve('new PID'); await flush()
    calls[0]!.resolve('old PID'); await flush()
    expect(applied).toEqual(['new PID'])
    vi.advanceTimersByTime(100); expect(calls).toHaveLength(3)
  })

  it('stop cancels requests and rejects late writes', async () => {
    poller.start(); poller.stop(); expect(calls[0]!.signal.aborted).toBe(true)
    calls[0]!.resolve('late'); await flush(); vi.advanceTimersByTime(1000)
    expect(applied).toEqual([]); expect(calls).toHaveLength(1); expect(vi.getTimerCount()).toBe(0)
    poller.refresh(); expect(calls).toHaveLength(1)
    poller.start(); expect(calls).toHaveLength(2)
    calls[1]!.resolve('visible'); await flush(); expect(applied).toEqual(['visible'])
  })

  it('retries backend errors without duplicate timers', async () => {
    poller.start(); calls[0]!.reject(new Error('offline')); await flush()
    vi.advanceTimersByTime(100); expect(calls).toHaveLength(2)
    calls[1]!.resolve('recovered'); await flush(); expect(applied).toEqual(['recovered'])
  })

  it('stop during the wait cancels the next refresh', async () => {
    poller.start(); calls[0]!.resolve('ok'); await flush()
    poller.stop(); vi.advanceTimersByTime(1000); expect(calls).toHaveLength(1)
  })
})
