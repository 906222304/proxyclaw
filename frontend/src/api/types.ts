export type ProxyProtocol = 'socks5' | 'http'
export type RuleProtocol = 'tcp' | 'udp' | 'both'
export type HijackSource = 'manual' | 'auto' | ''

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
  /** Why the flow is IGNORED; "none" when proxied. Same verdict the data path uses. */
  route_reason?: string
  process_name: string
}

export interface NetworkConnection extends TcpConnection {
  protocol: 'TCP' | 'UDP'
}

export interface Stats {
  hijacked_pids: number
  auto_rules_count: number
}
