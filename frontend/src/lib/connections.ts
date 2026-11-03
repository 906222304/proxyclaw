import type { NetworkConnection } from '@/api/types'

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
}

export type ColumnKey = 'process_name' | 'pid' | 'protocol' | 'remote' | 'state' | 'proxy_status' | 'local_port'

export interface ColumnDef {
  key: ColumnKey
  header: string
  /** CSS grid track; exactly one column per view is flexible. */
  width: string
  mono?: boolean
}

export function remoteOf(c: NetworkConnection): string {
  return c.remote_ip ? `${c.remote_ip}:${c.remote_port}` : ''
}

/**
 * Columns for the view. Every column except Process has a bounded content
 * width; Process absorbs the slack. In the per-PID view there is no Process
 * column, so Remote flexes instead.
 */
export function columnsFor(allProcesses: boolean): ColumnDef[] {
  const cols: ColumnDef[] = []
  if (allProcesses) cols.push({ key: 'process_name', header: '进程', width: 'minmax(150px, 1fr)' })
  cols.push(
    { key: 'pid', header: 'PID', width: '76px', mono: true },
    { key: 'protocol', header: '协议', width: '72px' },
    { key: 'remote', header: '远端地址', width: allProcesses ? 'minmax(150px, 210px)' : 'minmax(160px, 1fr)', mono: true },
    { key: 'state', header: '连接状态', width: '124px' },
    { key: 'proxy_status', header: '代理状态', width: '96px' },
    { key: 'local_port', header: '本地端口', width: '96px', mono: true },
  )
  return cols
}

export function sortValue(c: NetworkConnection, key: ColumnKey): string | number {
  switch (key) {
    case 'remote': return remoteOf(c)
    case 'pid': return c.pid
    case 'local_port': return c.local_port
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
