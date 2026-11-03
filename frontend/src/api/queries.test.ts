// @vitest-environment jsdom
// (TanStack Query disables refetchInterval when there is no window.)
import { QueryClient, QueryObserver, focusManager } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  ACTIVITY_TIMEOUT_MS, CONNECTIONS_INTERVAL_MS, STATS_INTERVAL_MS,
  connectionsQuery, createQueryClient, isActive, mergeActivity, statsQuery,
} from './queries'

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), { status: 200 })
}

describe('mergeActivity', () => {
  it('stamps current pids and keeps unexpired old ones', () => {
    const prev = { 1: 1_000, 2: 1_000, 3: 1_000 - ACTIVITY_TIMEOUT_MS }
    const next = mergeActivity(prev, [2, 4], 5_000)
    expect(next).toEqual({ 1: 1_000, 2: 5_000, 4: 5_000 })
  })
  it('isActive honours the timeout', () => {
    expect(isActive({ 7: 0 }, 7, ACTIVITY_TIMEOUT_MS - 1)).toBe(true)
    expect(isActive({ 7: 0 }, 7, ACTIVITY_TIMEOUT_MS)).toBe(false)
    expect(isActive(undefined, 7)).toBe(false)
  })
})

describe('polling via refetchInterval', () => {
  let client: QueryClient
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    vi.useFakeTimers()
    focusManager.setFocused(true)
    client = createQueryClient()
    // QueryClientProvider does this in the app: it subscribes the cache to
    // focus (visibility) changes.
    client.mount()
    fetchMock = vi.fn(async () => jsonResponse({ hijacked_pids: 1, auto_rules_count: 2 }))
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => {
    client.unmount()
    client.clear()
    focusManager.setFocused(undefined)
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('polls /api/stats on its interval and pauses while hidden', async () => {
    const obs = new QueryObserver(client, statsQuery)
    const unsub = obs.subscribe(() => {})
    await vi.advanceTimersByTimeAsync(0)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0]![0]).toBe('/api/stats')

    await vi.advanceTimersByTimeAsync(STATS_INTERVAL_MS)
    expect(fetchMock).toHaveBeenCalledTimes(2)

    // Hidden window: no polling at all.
    focusManager.setFocused(false)
    await vi.advanceTimersByTimeAsync(STATS_INTERVAL_MS * 5)
    expect(fetchMock).toHaveBeenCalledTimes(2)

    // Visible again: refetch at once, then resume the interval.
    focusManager.setFocused(true)
    await vi.advanceTimersByTimeAsync(0)
    expect(fetchMock).toHaveBeenCalledTimes(3)
    await vi.advanceTimersByTimeAsync(STATS_INTERVAL_MS)
    expect(fetchMock).toHaveBeenCalledTimes(4)

    unsub()
    await vi.advanceTimersByTimeAsync(STATS_INTERVAL_MS * 3)
    expect(fetchMock).toHaveBeenCalledTimes(4)
    expect(client.getQueryData(statsQuery.queryKey)).toEqual({ hijacked_pids: 1, auto_rules_count: 2 })
  })

  it('never runs two requests for one key at once', async () => {
    let release!: () => void
    fetchMock.mockImplementation(() => new Promise<Response>(r => {
      release = () => r(jsonResponse({ hijacked_pids: 0, auto_rules_count: 0 }))
    }))
    const unsub = new QueryObserver(client, statsQuery).subscribe(() => {})
    await vi.advanceTimersByTimeAsync(STATS_INTERVAL_MS * 3)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    release()
    await vi.advanceTimersByTimeAsync(0)
    unsub()
  })

  it('keys connections by pid and hides system pids only in the all view', async () => {
    const tcp = [
      { pid: 0, local_ip: '0.0.0.0', local_port: 1, remote_ip: '', remote_port: 0, state: 'TIME_WAIT' },
      { pid: 4, local_ip: '0.0.0.0', local_port: 2, remote_ip: '', remote_port: 0, state: 'LISTEN' },
      { pid: 42, local_ip: '10.0.0.1', local_port: 3, remote_ip: '1.1.1.1', remote_port: 443, state: 'ESTABLISHED' },
    ]
    fetchMock.mockImplementation(async (url: string) => jsonResponse(url.startsWith('/api/tcp') ? tcp : []))

    const all = await client.fetchQuery(connectionsQuery(undefined))
    expect(all.map(c => c.pid)).toEqual([42])
    expect(all[0]!.protocol).toBe('TCP')

    const one = await client.fetchQuery(connectionsQuery(4))
    expect(one.map(c => c.pid)).toEqual([0, 4, 42])
    expect(fetchMock.mock.calls.map(c => c[0])).toContain('/api/tcp?pid=4')

    // Different keys: a selection switch never sees the other view's rows.
    expect(connectionsQuery(undefined).queryKey).not.toEqual(connectionsQuery(4).queryKey)
    expect(connectionsQuery(4).refetchInterval).toBe(CONNECTIONS_INTERVAL_MS)
  })
})
