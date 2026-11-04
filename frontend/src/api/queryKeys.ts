// Every piece of server state lives in the TanStack Query cache under one of
// these keys. Components read through useQuery; the push channel and
// mutations write through setQueryData / invalidateQueries. Nothing else
// keeps a copy of server data.
export const queryKeys = {
  /** Process tree. Push-only: filled by `process_update`, never fetched. */
  processTree: ['processTree'] as const,
  processDetail: (pid: number) => ['processDetail', pid] as const,
  /** Object URL of an exe's icon (null = none). Fetched once per name per session. */
  processIcon: (name: string) => ['processIcon', name] as const,
  stats: ['stats'] as const,
  /** TCP+UDP connections for one PID, or for all processes ('all'). */
  connections: (pid: number | undefined) => ['connections', pid ?? 'all'] as const,
  /** pid -> last time (ms) it was seen owning a socket; drives tree dimming. */
  activity: ['activity'] as const,
  autoRules: ['autoRules'] as const,
  proxyGroups: ['proxyGroups'] as const,
  proxyTest: (id: number) => ['proxyTest', id] as const,
  config: ['config'] as const,
  autostart: ['autostart'] as const,
  log: ['log'] as const,
}
