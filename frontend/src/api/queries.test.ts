// @vitest-environment jsdom
// (TanStack Query disables refetchInterval when there is no window.)
import { QueryClient, QueryObserver, focusManager } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  ACTIVITY_REFRESH_MS, ACTIVITY_TIMEOUT_MS, CONNECTIONS_INTERVAL_MS, STATS_INTERVAL_MS,
  activityQuery, connectionsQuery, createQueryClient, isActive, mergeActivity, statsQuery,
  type ActivityMap,
} from './queries'
import { queryKeys } from './queryKeys'

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), { status: 200 })
}

describe('mergeActivity', () => {
  it('stamps current pids and keeps unexpired old ones', () => {
    const now = 1_000 + ACTIVITY_REFRESH_MS
    const prev = { 1: 1_000, 2: 1_000, 3: now - ACTIVITY_TIMEOUT_MS }
    const next = mergeActivity(prev, [2, 4], now)
    expect(next).toEqual({ 1: 1_000, 2: now, 4: now })
  })
  it('re-stamps a pid at most every ACTIVITY_REFRESH_MS and keeps the map identity when nothing changed', () => {
    const prev = mergeActivity(undefined, [7, 8], 1_000)
    expect(prev).toEqual({ 7: 1_000, 8: 1_000 })
    // Same pids 2 s later (the next connection poll): same object.
    expect(mergeActivity(prev, [8, 7, 7], 3_000)).toBe(prev)
    // A new pid, or a stamp old enough to refresh, yields a new map.
    expect(mergeActivity(prev, [7, 8, 9], 3_000)).toEqual({ 7: 1_000, 8: 1_000, 9: 3_000 })
    expect(mergeActivity(prev, [7], 1_000 + ACTIVITY_REFRESH_MS)).toEqual({ 7: 1_000 + ACTIVITY_REFRESH_MS, 8: 1_000 })
    // Expiry is a change too.
    expect(mergeActivity(prev, [7], 1_000 + ACTIVITY_TIMEOUT_MS)).toEqual({ 7: 1_000 + ACTIVITY_TIMEOUT_MS })
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

  const row = (pid: number, local_port: number, state = 'ESTABLISHED') =>
    ({ pid, local_ip: '10.0.0.1', local_port, remote_ip: '1.1.1.1', remote_port: 443, state })

  it('keys connections by pid and hides system pids only in the all view', async () => {
    const tcp = [row(0, 1, 'TIME_WAIT'), row(4, 2, 'LISTEN'), row(42, 3)]
    const udp = [row(42, 5353, 'BOUND')]
    fetchMock.mockImplementation(async () => jsonResponse({ tcp, udp, active_pids: [0, 4, 42] }))

    const all = await client.fetchQuery(connectionsQuery(undefined))
    expect(all.map(c => [c.pid, c.protocol])).toEqual([[42, 'TCP'], [42, 'UDP']])

    const one = await client.fetchQuery(connectionsQuery(4))
    expect(one.map(c => c.pid)).toEqual([0, 4, 42, 42])
    expect(fetchMock.mock.calls.map(c => c[0])).toEqual(['/api/connections', '/api/connections?pid=4'])

    // Different keys: a selection switch never sees the other view's rows.
    expect(connectionsQuery(undefined).queryKey).not.toEqual(connectionsQuery(4).queryKey)
    expect(connectionsQuery(4).refetchInterval).toBe(CONNECTIONS_INTERVAL_MS)
  })

  it('one poll feeds the activity map, also while a pid is selected', async () => {
    // The selected view returns only pid 42's rows, but active_pids covers
    // every process: the tree keeps dimming correctly.
    fetchMock.mockImplementation(async () => jsonResponse({ tcp: [row(42, 3)], udp: [], active_pids: [4, 42, 77] }))
    const activity = new QueryObserver(client, activityQuery)
    const unsubActivity = activity.subscribe(() => {})
    const unsub = new QueryObserver(client, connectionsQuery(42)).subscribe(() => {})
    await vi.advanceTimersByTimeAsync(0)

    const map = client.getQueryData<ActivityMap>(queryKeys.activity)!
    expect(Object.keys(map).map(Number)).toEqual([4, 42, 77])
    expect(isActive(map, 77)).toBe(true)
    expect(activity.getCurrentResult().data).toBe(map)

    // Next poll with the same pids keeps the same map (no tree re-render).
    await vi.advanceTimersByTimeAsync(CONNECTIONS_INTERVAL_MS)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(client.getQueryData(queryKeys.activity)).toBe(map)

    unsub()
    unsubActivity()
  })

  it('makes 30 requests a minute in total (was 72: 2 x 30 connection + 2 x 6 activity)', async () => {
    fetchMock.mockImplementation(async () => jsonResponse({ tcp: [], udp: [], active_pids: [] }))
    // What the network tab mounts: the table's poll and the tree's activity reader.
    const unsubTable = new QueryObserver(client, connectionsQuery(undefined)).subscribe(() => {})
    const unsubTree = new QueryObserver(client, activityQuery).subscribe(() => {})
    await vi.advanceTimersByTimeAsync(0)
    fetchMock.mockClear()
    await vi.advanceTimersByTimeAsync(60_000)
    expect(fetchMock).toHaveBeenCalledTimes(60_000 / CONNECTIONS_INTERVAL_MS)
    expect(new Set(fetchMock.mock.calls.map(c => c[0]))).toEqual(new Set(['/api/connections']))
    unsubTable()
    unsubTree()
  })
})
