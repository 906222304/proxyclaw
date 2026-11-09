import { QueryClient, queryOptions, useQuery } from '@tanstack/react-query'
import {
  fetchProcessIcon,
  getAutoRules,
  getAutostart,
  getConfig,
  getConnections,
  getLog,
  getProcessDetail,
  getProxyGroups,
  getStats,
  testProxyGroup,
  toNetworkConnections,
} from './client'
import { queryKeys } from './queryKeys'
import type { NetworkConnection, ProcessInfo, ProxyTestResult } from './types'

// Polling contract (replaces the hand-written asyncPoller):
// - refetchInterval drives the poll; TanStack Query never runs two fetches
//   for one key at once, and the next tick only fires after the interval.
// - refetchIntervalInBackground: false pauses the poll while the document is
//   hidden (WebView2 IsVisible=false on minimize / tray hide).
// - refetchOnWindowFocus fires immediately when the window becomes visible
//   again, so restored views are never stale by a whole interval.
// - Each view (e.g. a selected PID) has its own key, so a late response for a
//   previous selection can never overwrite the current one.
const POLL = {
  refetchIntervalInBackground: false,
  refetchOnWindowFocus: true,
  staleTime: 0,
} as const

export const STATS_INTERVAL_MS = 3_000
export const CONNECTIONS_INTERVAL_MS = 2_000
/**
 * Activity stamps are refreshed at most this often. The activity map rides
 * on the 2 s connection poll, but re-stamping a PID every poll would hand
 * the process tree a new map (and a re-render) every 2 s for nothing.
 */
export const ACTIVITY_REFRESH_MS = 10_000
export const LOG_INTERVAL_MS = 3_000
export const ACTIVITY_TIMEOUT_MS = 30_000

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // Local backend: a failure is retried by the next poll, not by a
        // burst of retries.
        retry: false,
        refetchOnWindowFocus: false,
        refetchOnReconnect: false,
        staleTime: 30_000,
      },
    },
  })
}

// pid 0 (Idle / orphaned TIME_WAIT sockets) and pid 4 (System) are noise in
// the "all processes" feed. When a process is explicitly selected we still
// show whatever it owns, including pid 0/4.
export const SYSTEM_PIDS = new Set([0, 4])

/** Exe icon as an object URL, or null (204 = no icon, or any failure). */
export function processIconQuery(name: string) {
  return queryOptions({
    queryKey: queryKeys.processIcon(name),
    queryFn: ({ signal }) => fetchProcessIcon(name, signal).catch(() => null),
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
  })
}

export const statsQuery = queryOptions({
  queryKey: queryKeys.stats,
  queryFn: ({ signal }) => getStats(signal),
  refetchInterval: STATS_INTERVAL_MS,
  ...POLL,
})

export type ActivityMap = Record<number, number>

/**
 * One poll (GET /api/connections) serves both the network-activity table and
 * the process tree's activity dimming. The table rows are the query's data;
 * `active_pids` (from the unfiltered listing, whatever the selected PID) is
 * merged into the activity cache entry as a side effect. Before v0.14 #3 the
 * tree ran its own 10 s poll of /api/tcp + /api/udp next to this one.
 */
export function connectionsQuery(pid: number | undefined) {
  return queryOptions({
    queryKey: queryKeys.connections(pid),
    queryFn: async ({ signal, client }): Promise<NetworkConnection[]> => {
      const res = await getConnections(pid, signal)
      client.setQueryData<ActivityMap>(queryKeys.activity,
        prev => mergeActivity(prev, res.active_pids, Date.now()))
      const rows = toNetworkConnections(res)
      return pid == null ? rows.filter(c => !SYSTEM_PIDS.has(c.pid)) : rows
    },
    refetchInterval: CONNECTIONS_INTERVAL_MS,
    ...POLL,
  })
}

/**
 * Merge a fresh socket listing into the last-seen map: every PID with a
 * socket now gets `now` (or keeps a stamp younger than ACTIVITY_REFRESH_MS);
 * PIDs without one keep their old stamp until it is older than
 * ACTIVITY_TIMEOUT_MS. Returns `prev` itself when nothing changed, so the
 * cache entry and its readers stay put.
 */
export function mergeActivity(prev: ActivityMap | undefined, pids: Iterable<number>, now: number): ActivityMap {
  const next: ActivityMap = {}
  let changed = prev == null
  for (const pid of pids) {
    if (pid in next) continue
    const old = prev?.[pid]
    if (old != null && now - old < ACTIVITY_REFRESH_MS) {
      next[pid] = old
    } else {
      next[pid] = now
      changed = true
    }
  }
  if (prev) {
    for (const [k, ts] of Object.entries(prev)) {
      const pid = Number(k)
      if (pid in next) continue
      if (now - ts < ACTIVITY_TIMEOUT_MS) next[pid] = ts
      else changed = true
    }
  }
  return changed ? next : prev!
}

export function isActive(map: ActivityMap | undefined, pid: number, now = Date.now()): boolean {
  const ts = map?.[pid]
  return ts != null && now - ts < ACTIVITY_TIMEOUT_MS
}

const EMPTY_ACTIVITY: ActivityMap = {}

/** Read-only view of the activity map; written by connectionsQuery, never fetched. */
export const activityQuery = queryOptions({
  queryKey: queryKeys.activity,
  queryFn: () => EMPTY_ACTIVITY,
  enabled: false,
  staleTime: Infinity,
  gcTime: Infinity,
})

const EMPTY_TREE: ProcessInfo[] = []

/** Push-only query: the cache is written by notify.ts; never fetched. */
export const processTreeQuery = queryOptions({
  queryKey: queryKeys.processTree,
  queryFn: () => EMPTY_TREE,
  enabled: false,
  staleTime: Infinity,
  gcTime: Infinity,
})

export function processDetailQuery(pid: number | undefined) {
  return queryOptions({
    queryKey: queryKeys.processDetail(pid ?? -1),
    queryFn: () => getProcessDetail(pid!),
    enabled: pid != null,
    // cmdline / image_path do not change while the process lives.
    staleTime: Infinity,
  })
}

export const autoRulesQuery = queryOptions({
  queryKey: queryKeys.autoRules,
  queryFn: getAutoRules,
})

export const proxyGroupsQuery = queryOptions({
  queryKey: queryKeys.proxyGroups,
  queryFn: getProxyGroups,
})

export const configQuery = queryOptions({
  queryKey: queryKeys.config,
  queryFn: getConfig,
  staleTime: 0,
})

export const autostartQuery = queryOptions({
  queryKey: queryKeys.autostart,
  queryFn: getAutostart,
})

export function logQuery(enabled: boolean, automatic: boolean) {
  return queryOptions({
    queryKey: queryKeys.log,
    queryFn: ({ signal }) => getLog(signal),
    enabled,
    refetchInterval: automatic ? LOG_INTERVAL_MS : false,
    ...POLL,
    refetchOnWindowFocus: automatic,
  })
}

/** Speed-test results are kept per group in the cache; run via fetchQuery. */
export function proxyTestQuery(id: number) {
  return queryOptions({
    queryKey: queryKeys.proxyTest(id),
    queryFn: async (): Promise<ProxyTestResult> => {
      try {
        return await testProxyGroup(id)
      } catch {
        return { error: '请求失败' }
      }
    },
    enabled: false,
    staleTime: Infinity,
    gcTime: Infinity,
  })
}

export function useProcessTree(): ProcessInfo[] {
  return useQuery(processTreeQuery).data ?? EMPTY_TREE
}
