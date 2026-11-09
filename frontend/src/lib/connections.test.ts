import { describe, expect, it } from 'vitest'
import { toNetworkConnections } from '@/api/client'
import type { NetworkConnection } from '@/api/types'
import { columnsFor, filterRows, hitInfo, hitTooltip, nextSort, rowId, sortRows, withHits } from './connections'

function conn(p: Partial<NetworkConnection>): NetworkConnection {
  return {
    pid: 1, local_ip: '127.0.0.1', local_port: 1000, remote_ip: '1.1.1.1', remote_port: 443,
    state: 'ESTABLISHED', dest: '', hijacked: false, pid_alive: true, proxy_status: 'DIRECT',
    process_name: 'a.exe', protocol: 'TCP', ...p,
  }
}

const rows = [
  conn({ pid: 30, process_name: 'chrome.exe', remote_ip: '10.0.0.2', local_port: 900, proxy_status: 'PROXIED' }),
  conn({ pid: 4, process_name: 'Code.exe', remote_ip: '10.0.0.10', local_port: 80, state: 'TIME_WAIT', protocol: 'UDP' }),
  conn({ pid: 200, process_name: 'curl.exe', remote_ip: '', remote_port: 0, local_port: 5000, state: 'BOUND', proxy_status: 'IGNORED' }),
]

describe('sorting', () => {
  it('keeps PID and protocol sortable through the folded columns', () => {
    const [proc, remote] = columnsFor(true)
    expect(proc!.sub?.key).toBe('pid')
    expect(remote!.sub?.key).toBe('protocol')
    expect(columnsFor(false)[0]!.sub?.key).toBe('protocol')
  })

  it('cycles asc → desc → none per column and restarts on a new column', () => {
    let s = nextSort(null, 'pid')
    expect(s).toEqual({ key: 'pid', dir: 'asc' })
    s = nextSort(s, 'pid')
    expect(s).toEqual({ key: 'pid', dir: 'desc' })
    expect(nextSort(s, 'pid')).toBeNull()
    expect(nextSort(s, 'state')).toEqual({ key: 'state', dir: 'asc' })
  })

  it('sorts numbers numerically and strings naturally, case-insensitive', () => {
    expect(sortRows(rows, { key: 'pid', dir: 'asc' }).map(r => r.pid)).toEqual([4, 30, 200])
    expect(sortRows(rows, { key: 'local_port', dir: 'desc' }).map(r => r.local_port)).toEqual([5000, 900, 80])
    expect(sortRows(rows, { key: 'process_name', dir: 'asc' }).map(r => r.process_name)).toEqual(['chrome.exe', 'Code.exe', 'curl.exe'])
    expect(sortRows(rows, { key: 'remote', dir: 'asc' }).map(r => r.remote_ip)).toEqual(['', '10.0.0.2', '10.0.0.10'])
  })

  it('returns input order when unsorted and is stable', () => {
    expect(sortRows(rows, null)).toBe(rows)
    const same = [conn({ pid: 1, local_port: 1 }), conn({ pid: 1, local_port: 2 })]
    expect(sortRows(same, { key: 'pid', dir: 'desc' }).map(r => r.local_port)).toEqual([1, 2])
  })
})

describe('quick filter', () => {
  it('matches raw values and Chinese labels, all words required', () => {
    expect(filterRows(rows, '').length).toBe(3)
    expect(filterRows(rows, 'CHROME').map(r => r.pid)).toEqual([30])
    expect(filterRows(rows, '10.0.0.1').map(r => r.pid)).toEqual([4])
    expect(filterRows(rows, '等待超时').map(r => r.pid)).toEqual([4])
    expect(filterRows(rows, 'time_wait').map(r => r.pid)).toEqual([4])
    expect(filterRows(rows, '已忽略').map(r => r.pid)).toEqual([200])
    expect(filterRows(rows, 'udp code').map(r => r.pid)).toEqual([4])
    expect(filterRows(rows, 'udp chrome')).toEqual([])
  })
})

describe('row identity and columns', () => {
  it('keeps dual-stack sockets apart', () => {
    expect(rowId(conn({ local_ip: '0.0.0.0' }))).not.toBe(rowId(conn({ local_ip: '::' })))
  })
  it('shows the process column only in the all-processes view', () => {
    expect(columnsFor(true).map(c => c.key)[0]).toBe('process_name')
    expect(columnsFor(false).map(c => c.key)).not.toContain('process_name')
  })
})

describe('hit info (v0.14 #4)', () => {
  const names = new Map([['r1', 'Chrome 代理'], ['r2', '开发工具']])
  const d = (p: Partial<NonNullable<NetworkConnection['decision']>>) => ({
    verdict: 'proxied' as const, reason: 'none', rule_id: 'r1', source: 'rule' as const, group: 0,
    config_version: 3, at_ms: new Date(2026, 0, 1, 9, 5, 7).getTime(), pid: 1, psn: 1, ...p,
  })

  it('names the recorded rule, its reason and when it was decided', () => {
    const info = hitInfo(conn({ decision: d({}), decision_source: 'recorded', hijacked: true }), names)
    expect(info).toMatchObject({ label: 'Chrome 代理', kind: 'rule', inherited: false, estimated: false, stale: false, reason: '按规则代理' })
    expect(hitTooltip(info).split('\n')).toEqual(['命中规则：Chrome 代理', '原因：按规则代理', '建立连接时记录 · 09:05:07'])
    const tree = hitInfo(conn({ decision: d({ source: 'tree', reason: 'rule_exclude_port', verdict: 'direct' }) }), names)
    expect(hitTooltip(tree)).toContain('命中规则：Chrome 代理（经进程树继承）')
    expect(hitTooltip(tree)).toContain('原因：命中规则的直连端口')
  })

  it('marks recomputed rows as estimated from the current rules', () => {
    const info = hitInfo(conn({ decision: null, decision_source: 'recomputed', hijacked: true, estimate: { source: 'tree', rule_id: 'r2' } }), names)
    expect(info).toMatchObject({ label: '开发工具', estimated: true, inherited: true })
    expect(hitTooltip(info)).toContain('无决定记录，按当前规则估算')
    expect(hitInfo(conn({ decision: null, decision_source: 'recomputed', estimate: { source: 'manual', rule_id: null } }), names).label).toBe('手动')
    // Not proxied now, no record: nothing to show.
    expect(hitInfo(conn({ decision: null, decision_source: 'recomputed' }), names)).toMatchObject({ label: '', kind: 'none', estimated: false })
  })

  it('flags decisions taken under older rules, but not quiet direct rows', () => {
    expect(hitInfo(conn({ decision: d({}), config_stale: true }), names).stale).toBe(true)
    expect(hitTooltip(hitInfo(conn({ decision: d({}), config_stale: true }), names))).toContain('规则已变更')
    const direct = d({ verdict: 'direct', reason: 'not-proxied', rule_id: null, source: null, group: null })
    expect(hitInfo(conn({ decision: direct, config_stale: true, hijacked: false }), names).stale).toBe(false)
    // ...unless the process is proxied now: the old connection is still direct.
    expect(hitInfo(conn({ decision: direct, config_stale: true, hijacked: true }), names).stale).toBe(true)
  })

  it('shows late / watchdog / pool / IPv6 reasons in Chinese instead of a rule', () => {
    for (const [reason, label] of [['late', '决定过晚'], ['watchdog', '看门狗放行'], ['pool_exhausted', '暂存池已满'], ['ipv6', 'IPv6 未接管']]) {
      const info = hitInfo(conn({ proxy_status: 'IGNORED', decision: d({ verdict: 'direct', reason: reason!, source: null, rule_id: null }) }), names)
      expect(info).toMatchObject({ label, kind: 'reason' })
      expect(info.reason).not.toBe('')
    }
  })

  it('resolves conflicts to names, a manual winner and deleted rules', () => {
    const info = hitInfo(conn({ decision: d({}), conflict: { manual: false, winner: 'r1', shadowed_rule_ids: ['r2', 'gone'] } }), names)
    expect(info.conflict).toEqual({ winner: 'Chrome 代理', shadowed: ['开发工具', '已删除的规则'] })
    expect(hitTooltip(info)).toContain('规则冲突：Chrome 代理 先匹配并生效，开发工具、已删除的规则 被忽略')
    const manual = hitInfo(conn({ decision: d({ source: 'manual', rule_id: null }), conflict: { manual: true, winner: null, shadowed_rule_ids: ['r1'] } }), names)
    expect(manual.label).toBe('手动')
    expect(manual.conflict).toEqual({ winner: '手动', shadowed: ['Chrome 代理'] })
    expect(hitInfo(conn({ decision: d({ rule_id: 'gone' }) }), names).label).toBe('已删除的规则')
  })

  it('sorts and filters by the rule', () => {
    const hits = withHits([
      conn({ pid: 1, decision: d({ rule_id: 'r2' }) }),
      conn({ pid: 2, decision: d({}), conflict: { manual: false, winner: 'r1', shadowed_rule_ids: ['r2'] } }),
      conn({ pid: 3 }),
    ], names)
    // zh-CN collation: unlabeled first, then Chinese before Latin.
    expect(sortRows(hits, { key: 'rule', dir: 'asc' }).map(r => r.pid)).toEqual([3, 1, 2])
    expect(filterRows(hits, '开发工具').map(r => r.pid)).toEqual([1])
    expect(filterRows(hits, '冲突').map(r => r.pid)).toEqual([2])
    expect(columnsFor(true).find(c => c.key === 'proxy_status')?.sub?.key).toBe('rule')
    expect(columnsFor(true)).toHaveLength(5)
  })

  it('tags rows decided under an older config_version', () => {
    const rec = { ...conn({}), decision: d({ config_version: 3 }) }
    const [stale, fresh, none] = toNetworkConnections({ active_pids: [], config_version: 4, udp: [], tcp: [rec, { ...rec, decision: d({ config_version: 4 }) }, { ...rec, decision: null }] })
    expect([stale!.config_stale, fresh!.config_stale, none!.config_stale]).toEqual([true, false, false])
    expect(toNetworkConnections({ active_pids: [], udp: [], tcp: [rec] })[0]!.config_stale).toBe(false)
  })
})
