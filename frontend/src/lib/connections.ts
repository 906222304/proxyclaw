import type { NetworkConnection as ApiConnection } from '@/api/types'

/** A row of the table: the API row plus its hit info (see withHits). */
export type NetworkConnection = ApiConnection & { hit?: HitInfo }

// Display translations; the protocol states sent by the API stay intact.
export const CONNECTION_STATES: Record<string, string> = {
  ESTABLISHED: '已连接', BOUND: '已绑定', LISTEN: '监听中', LISTENING: '监听中',
  SYN_SENT: '正在连接', SYN_RECEIVED: '收到连接请求', SYN_RCVD: '收到连接请求',
  FIN_WAIT_1: '等待关闭 1', FIN_WAIT_2: '等待关闭 2', CLOSE_WAIT: '等待关闭',
  CLOSING: '正在关闭', LAST_ACK: '等待最终确认', TIME_WAIT: '等待超时',
  CLOSED: '已关闭', DELETE_TCB: '已删除', UNKNOWN: '未知',
}

export const PROXY_STATES: Record<string, string> = { PROXIED: '已代理', IGNORED: '已忽略', DIRECT: '直连' }

export const ROUTE_REASONS: Record<string, string> = {
  global_exclude: '命中全局排除网段',
  rule_exclude: '命中规则的直连网段',
  rule_exclude_port: '命中规则的直连端口',
  rule_include_cidr_miss: '不在规则的仅代理网段内',
  rule_include_port_miss: '不在规则的代理端口内',
  rule_protocol: '规则未启用该协议',
  late: '代理决定晚于看门狗放行，已直连',
  watchdog: '未及时收到决定，看门狗放行直连',
  pool_exhausted: 'SYN 暂存池已满，直连放行',
  ipv6: 'IPv6 未接管，直连',
}

/** Decision reasons that are not route reasons (tooltip "原因" line). */
export const DECISION_REASONS: Record<string, string> = {
  none: '按规则代理',
  self: 'ProxyClaw 自身的连接，直连',
  'unknown-pid': '无法识别所属进程，直连',
  'not-proxied': '进程未命中任何规则，直连',
  ...ROUTE_REASONS,
}

/**
 * Reasons that decided the connection regardless of any rule: the cell shows
 * the reason itself instead of a rule name.
 */
export const REASON_LABELS: Record<string, string> = {
  late: '决定过晚',
  watchdog: '看门狗放行',
  pool_exhausted: '暂存池已满',
  ipv6: 'IPv6 未接管',
}

export const MANUAL_LABEL = '手动'
export const DELETED_RULE_LABEL = '已删除的规则'

/** What decided a connection, ready for the 代理 · 规则 cell (v0.14 #4). */
export interface HitInfo {
  /** Short cell text: rule name, 手动, or a reason label; '' = nothing to show. */
  label: string
  kind: 'rule' | 'manual' | 'reason' | 'none'
  /** Rule matched through a rule-matched ancestor (process tree). */
  inherited: boolean
  /** No decision record: estimated from the current rules. */
  estimated: boolean
  /** Decided under an older routing configuration than the current one. */
  stale: boolean
  /** Chinese reason ('' when unknown). */
  reason: string
  /** Decision time (recorded rows). */
  atMs?: number
  /** Other rules that also match the process (names), under the current rules. */
  conflict?: { winner: string; shadowed: string[] }
}

export type RuleNames = ReadonlyMap<string, string>

export function ruleNameOf(id: string | null | undefined, names: RuleNames): string {
  if (!id) return ''
  return names.get(id) ?? DELETED_RULE_LABEL
}

/**
 * Hit info for one row. Recorded rows read their decision (what the data
 * path decided at CONNECT, kept when rules change); recomputed rows use the
 * backend's current-rules estimate; plain direct rows of unmatched
 * processes and listening sockets have no label.
 */
export function hitInfo(c: ApiConnection, names: RuleNames): HitInfo {
  const d = c.decision
  const info: HitInfo = { label: '', kind: 'none', inherited: false, estimated: false, stale: false, reason: '' }
  const reasonKey = d?.reason ?? c.route_reason
  if (reasonKey) info.reason = DECISION_REASONS[reasonKey] ?? ''

  const source = d ? d.source : c.estimate?.source ?? null
  const ruleId = d ? d.rule_id : c.estimate?.rule_id ?? null
  if (d && REASON_LABELS[d.reason]) {
    info.label = REASON_LABELS[d.reason]!
    info.kind = 'reason'
  } else if (source === 'manual') {
    info.label = MANUAL_LABEL
    info.kind = 'manual'
  } else if ((source === 'rule' || source === 'tree') && ruleId) {
    info.label = ruleNameOf(ruleId, names)
    info.kind = 'rule'
    info.inherited = source === 'tree'
  }
  info.estimated = !d && c.decision_source === 'recomputed' && info.kind !== 'none'
  if (d) info.atMs = d.at_ms
  // The hint matters where a rule / hijack was involved, or the process is
  // proxied now although this connection was decided direct. A plain direct
  // row of a still-unmatched process stays quiet after unrelated edits.
  info.stale = !!c.config_stale && (source != null || c.hijacked)
  if (c.conflict && c.conflict.shadowed_rule_ids.length > 0) {
    info.conflict = {
      winner: c.conflict.manual ? MANUAL_LABEL : ruleNameOf(c.conflict.winner, names),
      shadowed: c.conflict.shadowed_rule_ids.map(id => ruleNameOf(id, names)),
    }
  }
  return info
}

function clock(ms: number): string {
  const t = new Date(ms)
  return [t.getHours(), t.getMinutes(), t.getSeconds()].map(n => String(n).padStart(2, '0')).join(':')
}

/** Tooltip lines for the 代理 · 规则 cell. */
export function hitTooltip(info: HitInfo): string {
  const lines: string[] = []
  if (info.kind === 'rule') lines.push(`命中规则：${info.label}${info.inherited ? '（经进程树继承）' : ''}`)
  else if (info.kind === 'manual') lines.push('手动代理')
  if (info.reason) lines.push(`原因：${info.reason}`)
  if (info.estimated) lines.push('无决定记录，按当前规则估算')
  else if (info.atMs) lines.push(`建立连接时记录 · ${clock(info.atMs)}`)
  if (info.stale) lines.push('规则已变更：此后路由配置有改动，这里仍显示建立连接时的决定')
  if (info.conflict) {
    lines.push(`规则冲突：${info.conflict.winner} 先匹配并生效，${info.conflict.shadowed.join('、')} 被忽略`)
  }
  return lines.join('\n')
}

export type ColumnKey = 'process_name' | 'pid' | 'protocol' | 'remote' | 'state' | 'proxy_status' | 'rule' | 'local_port'

export interface ColumnDef {
  key: ColumnKey
  header: string
  /** CSS grid track; exactly one column per view is flexible. */
  width: string
  mono?: boolean
  /** Folded-in column with its own sort target in the header (PID, protocol). */
  sub?: { key: ColumnKey; header: string; before?: boolean }
}

export function remoteOf(c: NetworkConnection): string {
  return c.remote_ip ? `${c.remote_ip}:${c.remote_port}` : ''
}

/**
 * Columns for the view. Protocol is folded into Remote (faint prefix), PID
 * into Process (muted suffix) and the hit rule into Proxy, so the
 * all-processes view has 5 columns. Every column except the first text
 * column has a bounded width; Process (or Remote in the per-PID view)
 * absorbs the slack. Budget at the 1024 px window (~730 px table): Process
 * ~200, Remote 176 (fits 168.63.129.16:32526), 代理 · 规则 180 (a rule name
 * of ~70 px plus both markers).
 */
export function columnsFor(allProcesses: boolean): ColumnDef[] {
  const cols: ColumnDef[] = []
  if (allProcesses) cols.push({ key: 'process_name', header: '进程', width: 'minmax(150px, 1fr)', sub: { key: 'pid', header: 'PID' } })
  cols.push(
    { key: 'remote', header: '远端地址', sub: { key: 'protocol', header: '协议', before: true }, width: allProcesses ? 'minmax(150px, 176px)' : 'minmax(200px, 1fr)', mono: true },
    { key: 'state', header: '连接状态', width: '100px' },
    { key: 'proxy_status', header: '代理', width: allProcesses ? 'minmax(140px, 180px)' : 'minmax(170px, 240px)', sub: { key: 'rule', header: '规则' } },
    { key: 'local_port', header: '本地端口', width: '76px', mono: true },
  )
  return cols
}

export function sortValue(c: NetworkConnection, key: ColumnKey): string | number {
  switch (key) {
    case 'remote': return remoteOf(c)
    case 'pid': return c.pid
    case 'local_port': return c.local_port
    case 'rule': return c.hit?.label ?? ''
    default: return c[key] ?? ''
  }
}

export type SortDir = 'asc' | 'desc'
export interface SortState { key: ColumnKey; dir: SortDir }

/** Header click cycles asc → desc → unsorted, like the old grid. */
export function nextSort(current: SortState | null, key: ColumnKey): SortState | null {
  if (!current || current.key !== key) return { key, dir: 'asc' }
  if (current.dir === 'asc') return { key, dir: 'desc' }
  return null
}

const collator = new Intl.Collator('zh-CN', { numeric: true, sensitivity: 'base' })

export function sortRows(rows: NetworkConnection[], sort: SortState | null): NetworkConnection[] {
  if (!sort) return rows
  const sign = sort.dir === 'asc' ? 1 : -1
  return rows
    .map((row, i) => ({ row, i }))
    .sort((a, b) => {
      const va = sortValue(a.row, sort.key)
      const vb = sortValue(b.row, sort.key)
      const cmp = typeof va === 'number' && typeof vb === 'number'
        ? va - vb
        : collator.compare(String(va), String(vb))
      return cmp !== 0 ? cmp * sign : a.i - b.i // stable
    })
    .map(x => x.row)
}

function searchText(c: NetworkConnection): string {
  return [
    c.process_name, c.pid, c.protocol, remoteOf(c), c.dest,
    c.state, CONNECTION_STATES[c.state],
    c.proxy_status, PROXY_STATES[c.proxy_status],
    c.hit?.label, c.hit?.reason, c.hit?.conflict ? '冲突' : '', c.hit?.stale ? '规则已变更' : '',
    c.local_port,
  ].filter(v => v != null && v !== '').join(' ').toLowerCase()
}

/**
 * Quick filter: every whitespace-separated word must appear somewhere in the
 * row (raw API values or their Chinese labels), case-insensitive.
 */
export function filterRows(rows: NetworkConnection[], text: string): NetworkConnection[] {
  const words = text.toLowerCase().split(/\s+/).filter(Boolean)
  if (words.length === 0) return rows
  return rows.filter(r => {
    const hay = searchText(r)
    return words.every(w => hay.includes(w))
  })
}

/**
 * Stable row id: include local_ip so dual-stack sockets (IPv4 + IPv6 on the
 * same local_port for the same PID) get distinct rows.
 */
export function rowId(c: NetworkConnection): string {
  return `${c.protocol}-${c.pid}-${c.local_ip}-${c.local_port}-${c.remote_ip}-${c.remote_port}`
}

export function stateTone(state: string): 'ok' | 'bound' | 'wait' | 'idle' {
  if (state === 'ESTABLISHED') return 'ok'
  if (state === 'BOUND') return 'bound'
  if (state === 'TIME_WAIT' || state === 'CLOSE_WAIT') return 'wait'
  return 'idle'
}

/** Rows with their hit info, for display, sorting and the quick filter. */
export function withHits(rows: ApiConnection[], names: RuleNames): NetworkConnection[] {
  return rows.map(r => ({ ...r, hit: hitInfo(r, names) }))
}
