import { useMutation, useQueryClient } from '@tanstack/react-query'
import { createAutoRule, deleteAutoRule, excludePid, unexcludePid, updateAutoRule } from './client'
import { queryKeys } from './queryKeys'
import type { AutoRule, ProxyGroup } from './types'

export type RulePayload = Omit<AutoRule, 'id' | 'matched_count' | 'excluded_count' | 'matched_pids'>

/** Invalidate everything a rule change can affect. */
function useRulesChanged() {
  const qc = useQueryClient()
  return () => Promise.all([
    qc.invalidateQueries({ queryKey: queryKeys.autoRules }),
    qc.invalidateQueries({ queryKey: queryKeys.stats }),
  ])
}

export function useSaveRule() {
  const changed = useRulesChanged()
  return useMutation({
    mutationFn: ({ id, payload }: { id?: string; payload: RulePayload }) =>
      id ? updateAutoRule(id, payload) : createAutoRule(payload),
    onSuccess: changed,
  })
}

export function useSetRulesEnabled() {
  const changed = useRulesChanged()
  return useMutation({
    mutationFn: ({ ids, enabled }: { ids: string[]; enabled: boolean }) =>
      Promise.all(ids.map(id => updateAutoRule(id, { enabled }))),
    onSettled: changed,
  })
}

/** Point a rule at another proxy group (its address follows the group). */
export function useSetRuleGroup() {
  const changed = useRulesChanged()
  return useMutation({
    mutationFn: ({ id, group }: { id: string; group: ProxyGroup }) =>
      updateAutoRule(id, {
        proxy_group_id: group.id,
        proxy: { type: group.type ?? 'socks5', host: group.host, port: group.port },
      }),
    onSettled: changed,
  })
}

/** Optimistic: drop the rules from the cache at once, refetch afterwards. */
export function useDeleteRules() {
  const qc = useQueryClient()
  const changed = useRulesChanged()
  return useMutation({
    mutationFn: (ids: string[]) => Promise.all(ids.map(id => deleteAutoRule(id))),
    onMutate: async (ids) => {
      await qc.cancelQueries({ queryKey: queryKeys.autoRules })
      const drop = new Set(ids)
      qc.setQueryData<AutoRule[]>(queryKeys.autoRules, old => old?.filter(r => !drop.has(r.id)))
    },
    onSettled: changed,
  })
}

/**
 * Make one process skip the proxy although auto rules match it: exclude the
 * PID from every rule that matches it. Runtime only (cleared when the
 * process exits). The backend re-applies rules and pushes a fresh process
 * tree itself; the rule list (matched_pids / excluded) is refetched here.
 */
export function useExcludeProcess() {
  const changed = useRulesChanged()
  return useMutation({
    mutationFn: ({ pid, ruleIds }: { pid: number; ruleIds: string[] }) =>
      Promise.all(ruleIds.map(id => excludePid(id, pid))),
    onSettled: changed,
  })
}

/** Undo useExcludeProcess for the given rules. */
export function useRestoreProcess() {
  const changed = useRulesChanged()
  return useMutation({
    mutationFn: ({ pid, ruleIds }: { pid: number; ruleIds: string[] }) =>
      Promise.all(ruleIds.map(id => unexcludePid(id, pid))),
    onSettled: changed,
  })
}
