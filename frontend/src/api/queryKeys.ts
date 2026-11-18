// Every piece of server state lives in the TanStack Query cache under one of
// these keys. Components read through useQuery; the push channel and
// mutations write through setQueryData / invalidateQueries. Nothing else
// keeps a copy of server data.
export const queryKeys = {
  /** Process tree. Push-only: filled by `process_update`, never fetched. */
  processTree: ['processTree'] as const,
  processDetail: (pid: number, psn: number) => ['processDetail', pid, psn] as const,
  /** Object URL of an exe's icon (null = none), per running process (pid) or per exe name (pid 0). */
  processIcon: (name: string, pid = 0, psn = 0) => ['processIcon', name.toLowerCase(), pid, psn] as const,
  stats: ['stats'] as const,
  /** DNS proxy state: fetched from /api/stats, then kept fresh by the `dns_status` push. */
  dnsStatus: ['dnsStatus'] as const,
  /** TCP+UDP connections for one PID, or for all processes ('all'), from GET /api/connections. */
  connections: (pid: number | undefined) => ['connections', pid ?? 'all'] as const,
  /** pid -> last time (ms) it was seen owning a socket; drives tree dimming. Written by the connections poll, never fetched. */
  activity: ['activity'] as const,
  autoRules: ['autoRules'] as const,
  proxyGroups: ['proxyGroups'] as const,
  proxyTest: (id: number) => ['proxyTest', id] as const,
  config: ['config'] as const,
  autostart: ['autostart'] as const,
  log: ['log'] as const,
}
