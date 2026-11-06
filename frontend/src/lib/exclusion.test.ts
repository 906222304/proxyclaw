import { describe, expect, it } from 'vitest'
import type { AutoRule } from '@/api/types'
import { excludeActionFor, excludedPids, hijackKind, ruleIdFromSource, rulesExcludingPid, rulesProxyingPid } from './exclusion'

const rule = (id: string, matched: { pid: number; excluded?: boolean }[]): AutoRule => ({
  id, name: id, enabled: true, process_name: 'app.exe', cmdline_pattern: '', hack_tree: true,
  dst_filter: { include_cidrs: [], exclude_cidrs: [], include_ports: [], exclude_ports: [] },
  proxy_group_id: 0, proxy: { type: 'socks5', host: '127.0.0.1', port: 7890 },
  matched_pids: matched.map(m => ({ pid: m.pid, name: 'app.exe', excluded: !!m.excluded })),
})

describe('hijack source parsing', () => {
  it('collapses backend sources to a kind', () => {
    expect(hijackKind('manual')).toBe('manual')
    expect(hijackKind('auto')).toBe('auto')
    expect(hijackKind('auto:r1')).toBe('auto')
    expect(hijackKind('tree:r1')).toBe('auto')
    expect(hijackKind('')).toBeNull()
    expect(hijackKind(undefined)).toBeNull()
  })
  it('extracts the rule id', () => {
    expect(ruleIdFromSource('auto:rule_a')).toBe('rule_a')
    expect(ruleIdFromSource('manual')).toBeNull()
    expect(ruleIdFromSource('auto')).toBeNull()
  })
})

describe('rule lookups', () => {
  const rules = [rule('a', [{ pid: 10 }, { pid: 11, excluded: true }]), rule('b', [{ pid: 10 }]), rule('c', [{ pid: 12 }])]
  it('finds every rule proxying a pid', () => {
    expect(rulesProxyingPid(rules, 10)).toEqual(['a', 'b'])
    expect(rulesProxyingPid(rules, 11)).toEqual([])
  })
  it('adds the source rule when the rule list is stale', () => {
    expect(rulesProxyingPid(rules, 99, 'auto:c')).toEqual(['c'])
    expect(rulesProxyingPid(rules, 99, 'auto:gone')).toEqual([])
  })
  it('finds exclusions', () => {
    expect(rulesExcludingPid(rules, 11)).toEqual(['a'])
    expect([...excludedPids(rules)]).toEqual([11])
    expect(excludedPids(undefined).size).toBe(0)
  })
})

describe('excludeActionFor', () => {
  const rules = [rule('a', [{ pid: 10 }, { pid: 11, excluded: true }]), rule('b', [{ pid: 10 }, { pid: 13, excluded: true }]), rule('c', [{ pid: 13 }])]
  it('offers exclusion from all matching rules for an auto-proxied process', () => {
    expect(excludeActionFor({ pid: 10, hijacked: true, hijack_source: 'auto:a' }, rules)).toEqual({ kind: 'exclude', ruleIds: ['a', 'b'] })
  })
  it('offers restore for an excluded process', () => {
    expect(excludeActionFor({ pid: 11, hijacked: false, hijack_source: '' }, rules)).toEqual({ kind: 'restore', ruleIds: ['a'] })
  })
  it('prefers exclude when another rule still proxies it', () => {
    expect(excludeActionFor({ pid: 13, hijacked: true, hijack_source: 'auto:c' }, rules)).toEqual({ kind: 'exclude', ruleIds: ['c'] })
  })
  it('offers nothing for manual hijacks, unmatched processes or no rules', () => {
    expect(excludeActionFor({ pid: 10, hijacked: true, hijack_source: 'manual' }, rules)).toBeNull()
    expect(excludeActionFor({ pid: 99, hijacked: false, hijack_source: '' }, rules)).toBeNull()
    expect(excludeActionFor({ pid: 10, hijacked: true, hijack_source: 'auto:a' }, [])).toBeNull()
    expect(excludeActionFor({ pid: 10, hijacked: true, hijack_source: 'auto:a' }, undefined)).toBeNull()
  })
  it('ignores stale matches when the process is no longer proxied', () => {
    expect(excludeActionFor({ pid: 10, hijacked: false, hijack_source: '' }, rules)).toBeNull()
  })
})
