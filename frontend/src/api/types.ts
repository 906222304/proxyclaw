export type ProxyProtocol = 'socks5' | 'http'
export type RuleProtocol = 'tcp' | 'udp' | 'both'
/** 'auto:<rule id>' from current backends; bare 'auto' from older ones. */
export type HijackSource = 'manual' | 'auto' | '' | `auto:${string}` | `tree:${string}`

export interface ProcessInfo {
  pid: number
  parent_pid: number
  name: string
  hijacked: boolean
  hijack_source?: HijackSource
  children?: ProcessInfo[]
  cmdline?: string
  image_path?: string
}

export interface ProxyTarget {
  type: ProxyProtocol
  host: string
  port: number
  user?: string
  password?: string
}

export interface TrafficFilter {
  include_cidrs: string[]
  exclude_cidrs: string[]
  include_ports: string[]
  exclude_ports: string[]
}

export interface AutoRule {
  id: string
  name: string
  enabled: boolean
  process_name: string
  cmdline_pattern: string
  image_path_pattern?: string
  hack_tree: boolean
  protocol?: RuleProtocol
  dst_filter: TrafficFilter
  proxy_group_id: number
  proxy: ProxyTarget
  matched_count?: number
  excluded_count?: number
  matched_pids?: { pid: number; name: string; excluded: boolean }[]
}

export interface ProxyGroup {
  id: number
  name: string
  host: string
  port: number
  type: ProxyProtocol
  test_url: string
}

export interface GroupInUseError {
  error: 'group_in_use'
  auto_rules: { id: string; name: string }[]
  manual_hijack_count: number
}

export type ProxyTestStageName = 'resolve' | 'connect' | 'handshake' | 'remote' | 'first_byte'

export interface ProxyTestStage {
  name: ProxyTestStageName | string
  ms: number
}

export interface ProxyTestResult {
  /** Present only on success (legacy contract). */
  latency_ms?: number
  error?: string
  /** Stage that failed: one of the stage names, or 'config' / 'queue'. */
  failed_stage?: string
  /** e.g. "HTTP 204", "TLS handshake". */
  detail?: string
  total_ms?: number
  target?: string
  stages?: ProxyTestStage[]
}

/**
 * What the data path decided for this connection at CONNECT / BIND time
 * (v0.14 #2). Not recomputed when rules change.
 */
export interface ConnectionDecision {
  verdict: 'proxied' | 'direct'
  /** "none" when proxied; otherwise self, unknown-pid, not-proxied, a route reason, late, watchdog, pool_exhausted, ipv6. */
  reason: string
  /** Auto rule id that classified the process (kept after the rule is deleted); null for manual / none. */
  rule_id: string | null
  source: 'rule' | 'tree' | 'manual' | null
  /** Proxy group id when proxied. */
  group: number | null
  config_version: number
  /** Wall clock, ms since the Unix epoch. */
  at_ms: number
  /** 0 when the layer that recorded it does not know the process (watchdog / pool exhausted). */
  pid: number
  psn: number
  /** reason "late" only: the decision that arrived too late. */
  late_verdict?: 'proxied' | 'direct'
}

/**
 * Other enabled rules that also match the row's process (v0.14 #4), under
 * the CURRENT rules. The first rule in config order (or a manual hijack)
 * decides the process; the rest are shadowed and never apply to it.
 */
export interface RuleConflict {
  /** The winner is a manual hijack (then `winner` is null). */
  manual: boolean
  winner: string | null
  shadowed_rule_ids: string[]
}

/** What decides the process now, for rows without a decision record (v0.14 #4). */
export interface DecisionEstimate {
  source: 'rule' | 'tree' | 'manual'
  rule_id: string | null
}

export interface TcpConnection {
  pid: number
  local_ip: string
  local_port: number
  remote_ip: string
  remote_port: number
  state: string
  dest: string
  hijacked: boolean
  pid_alive: boolean
  proxy_status: string
  /** Why the flow is IGNORED; "none" when proxied. From the recorded decision when there is one. */
  route_reason?: string
  /** Recorded decision; null when the row has none (see decision_source). */
  decision?: ConnectionDecision | null
  /** "recorded": from the decision record; "recomputed": no record, evaluated against the current rules; "none": listening socket. */
  decision_source?: 'recorded' | 'recomputed' | 'none'
  /** Present only when another rule also matches the process. */
  conflict?: RuleConflict
  /** Recomputed rows of a process proxied now: the current rule / manual hijack. */
  estimate?: DecisionEstimate
  process_name: string
}

export interface NetworkConnection extends TcpConnection {
  protocol: 'TCP' | 'UDP'
  /** The recorded decision predates the current routing configuration. */
  config_stale?: boolean
}

/** GET /api/connections: the UI's single connection poll. */
export interface ConnectionsResponse {
  tcp: TcpConnection[]
  udp: TcpConnection[]
  /** Every PID owning a socket in the unfiltered listing (sorted), whatever the pid filter. */
  active_pids: number[]
  /** Engine routing configuration version when the rows were built. */
  config_version?: number
}

export interface Stats {
  hijacked_pids: number
  auto_rules_count: number
}
