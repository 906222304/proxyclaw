import { useMutation, useQueryClient } from '@tanstack/react-query'
import { createAutoRule, deleteAutoRule, updateAutoRule } from './client'
import { queryKeys } from './queryKeys'
import type { AutoRule } from './types'

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
