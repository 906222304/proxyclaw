import type { AutoRule, ProcessInfo } from '@/api/types'

// Per-process exclusion from auto rules ("此进程不走代理").
//
// Backend semantics (rule_service / rule_engine_v3): an exclusion is a
// runtime-only (rule id, PID) pair. It is not written to config.json and is
// dropped when the process exits, so a restarted process is proxied again.
// It covers that one PID: descendants are not excluded with it. New
// connections go direct at once; connections already open stay on the proxy
// until they close.

export type HijackKind = 'manual' | 'auto'

/**
 * The pushed tree reports `hijack_source` as 'manual', 'auto:<rule id>' or
 * 'tree:<rule id>' (older builds: bare 'auto'). Collapse it to its kind.
 */
export function hijackKind(source: string | null | undefined): HijackKind | null {
  if (!source) return null
  if (source === 'manual') return 'manual'
  if (source === 'auto' || source.startsWith('auto:') || source.startsWith('tree:')) return 'auto'
  return null
}

/** Rule id carried by an auto hijack source, if any. */
export function ruleIdFromSource(source: string | null | undefined): string | null {
  if (!source) return null
  const m = /^(?:auto|tree):(.+)$/.exec(source)
  return m ? m[1]! : null
}

/** Ids of the rules that currently proxy `pid` (not excluded). */
export function rulesProxyingPid(rules: AutoRule[], pid: number, source?: string | null): string[] {
  const ids = rules
    .filter(r => r.matched_pids?.some(p => p.pid === pid && !p.excluded))
    .map(r => r.id)
  const fromSource = ruleIdFromSource(source)
  if (fromSource && !ids.includes(fromSource) && rules.some(r => r.id === fromSource)) ids.push(fromSource)
  return ids
}

/** Ids of the rules `pid` is excluded from. */
export function rulesExcludingPid(rules: AutoRule[], pid: number): string[] {
  return rules
    .filter(r => r.matched_pids?.some(p => p.pid === pid && p.excluded))
    .map(r => r.id)
}

/** Every PID excluded from at least one rule. */
export function excludedPids(rules: AutoRule[] | undefined): Set<number> {
  const set = new Set<number>()
  for (const r of rules ?? []) {
    for (const p of r.matched_pids ?? []) if (p.excluded) set.add(p.pid)
  }
  return set
}

export type ExcludeAction =
  | { kind: 'exclude'; ruleIds: string[] }
  | { kind: 'restore'; ruleIds: string[] }

/**
 * What the selected-process menu offers. Manually proxied processes get
 * nothing here (the tree's 取消代理 covers them). A process still proxied by
 * some rule offers exclusion from all of those rules, even if it is already
 * excluded from another one; otherwise an excluded process offers 恢复代理.
 */
export function excludeActionFor(process: Pick<ProcessInfo, 'pid' | 'hijacked' | 'hijack_source'>, rules: AutoRule[] | undefined): ExcludeAction | null {
  if (!rules || rules.length === 0) return null
  if (hijackKind(process.hijack_source) === 'manual') return null
  const proxying = process.hijacked ? rulesProxyingPid(rules, process.pid, process.hijack_source) : []
  if (proxying.length > 0) return { kind: 'exclude', ruleIds: proxying }
  const excluded = rulesExcludingPid(rules, process.pid)
  if (excluded.length > 0) return { kind: 'restore', ruleIds: excluded }
  return null
}
