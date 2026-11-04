import { useQuery } from '@tanstack/react-query'
import { ClipboardList, Pencil, Plus, Power, PowerOff, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useDeleteRules, useSetRulesEnabled } from '@/api/mutations'
import { autoRulesQuery, proxyGroupsQuery } from '@/api/queries'
import type { AutoRule } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Dialog } from '@/components/ui/dialog'
import { Badge, Checkbox, EmptyState, Segmented } from '@/components/ui/misc'
import { SearchInput } from '@/components/ui/search-input'
import { Switch } from '@/components/ui/switch'
import { pushError } from '@/lib/toast'
import { cn } from '@/lib/utils'

type StatusFilter = 'all' | 'active' | 'disabled'

export function filterRules(rules: AutoRule[], status: StatusFilter, query: string): AutoRule[] {
  let out = rules
  if (status === 'active') out = out.filter(r => r.enabled)
  if (status === 'disabled') out = out.filter(r => !r.enabled)
  const q = query.toLowerCase().trim()
  if (q) out = out.filter(r => r.name.toLowerCase().includes(q) || r.process_name.toLowerCase().includes(q))
  return out
}

export function AutoRules({ onAdd, onEdit }: {
  onAdd: () => void
  onEdit: (rule: AutoRule) => void
}) {
  const { data: rules = [] } = useQuery(autoRulesQuery)
  const { data: groups = [] } = useQuery(proxyGroupsQuery)
  const groupName = useMemo(() => new Map(groups.map(g => [g.id, g.name])), [groups])

  const [query, setQuery] = useState('')
  const [status, setStatus] = useState<StatusFilter>('all')
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set())
  const [pendingDelete, setPendingDelete] = useState<{ ids: string[]; label: string } | null>(null)

  const setEnabled = useSetRulesEnabled()
  const del = useDeleteRules()

  const visible = useMemo(() => filterRules(rules, status, query), [rules, status, query])
  const activeCount = rules.filter(r => r.enabled).length
  const allSelected = visible.length > 0 && visible.every(r => selected.has(r.id))
  const someSelected = selected.size > 0 && !allSelected

  const toggleAll = () => {
    setSelected(allSelected ? new Set() : new Set([...selected, ...visible.map(r => r.id)]))
  }
  const toggleOne = (id: string) => {
    const next = new Set(selected)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setSelected(next)
  }

  const batchEnable = (enabled: boolean) => {
    const ids = rules.filter(r => selected.has(r.id) && r.enabled !== enabled).map(r => r.id)
    setEnabled.mutate({ ids, enabled }, {
      onSuccess: () => setSelected(new Set()),
      onError: e => pushError(e, enabled ? '启用规则失败' : '停用规则失败'),
    })
  }
  const toggleRule = (rule: AutoRule) => {
    setEnabled.mutate({ ids: [rule.id], enabled: !rule.enabled }, {
      onError: e => pushError(e, '切换规则失败'),
    })
  }
  const confirmDelete = () => {
    if (!pendingDelete) return
    const { ids } = pendingDelete
    setPendingDelete(null)
    setSelected(new Set())
    del.mutate(ids, { onError: e => pushError(e, '删除规则失败') })
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex h-12 shrink-0 items-center gap-3 px-5">
        <Checkbox checked={allSelected} indeterminate={someSelected} onChange={toggleAll} label="全选" />
        {selected.size === 0 ? (
          <>
            <SearchInput value={query} onChange={setQuery} placeholder="搜索规则…" className="w-60" />
            <Segmented
              value={status}
              onChange={setStatus}
              className="ml-auto"
              options={[
                { value: 'all', label: `全部 ${rules.length}` },
                { value: 'active', label: `已启用 ${activeCount}` },
                { value: 'disabled', label: `已停用 ${rules.length - activeCount}` },
              ]}
            />
            <Button size="sm" variant="primary" onClick={onAdd}><Plus /> 添加规则</Button>
          </>
        ) : (
          <>
            <span className="text-xs font-medium text-primary">已选 {selected.size} 条</span>
            <div className="ml-2 flex items-center gap-1.5">
              <Button size="sm" disabled={setEnabled.isPending} onClick={() => batchEnable(true)}><Power /> 启用</Button>
              <Button size="sm" disabled={setEnabled.isPending} onClick={() => batchEnable(false)}><PowerOff /> 停用</Button>
              <Button
                size="sm"
                className="text-destructive"
                disabled={setEnabled.isPending}
                onClick={() => setPendingDelete({ ids: [...selected], label: `选中的 ${selected.size} 条规则` })}
              >
                <Trash2 /> 删除
              </Button>
            </div>
            <Button size="sm" variant="ghost" className="ml-auto" onClick={() => setSelected(new Set())}>取消</Button>
          </>
        )}
      </div>

      <div className="thin-scrollbar min-h-0 flex-1 overflow-auto px-5 pb-5">
        {visible.length === 0 ? (
          <EmptyState
            icon={<ClipboardList />}
            title={query || status !== 'all'
              ? '没有找到匹配的规则。'
              : <>暂无规则，点击 <strong>添加规则</strong> 创建第一条规则。</>}
          />
        ) : (
          <div className="divide-y divide-border overflow-hidden rounded-xl border border-border bg-card">
            {visible.map(rule => (
              <div
                key={rule.id}
                className={cn('group flex items-center gap-3 px-4 py-3 transition-colors', selected.has(rule.id) ? 'bg-selected' : 'hover:bg-muted/50')}
              >
                <Checkbox checked={selected.has(rule.id)} onChange={() => toggleOne(rule.id)} label={`选择 ${rule.name}`} />
                <Switch
                  checked={rule.enabled}
                  onCheckedChange={() => toggleRule(rule)}
                  aria-label={rule.enabled ? '停用规则' : '启用规则'}
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className={cn('truncate text-sm font-medium', !rule.enabled && 'text-muted-foreground')}>{rule.name}</span>
                    {rule.protocol === 'udp' && <Badge tone="green">UDP</Badge>}
                    {rule.protocol === 'both' && <Badge tone="violet">TCP+UDP</Badge>}
                    {(rule.matched_count ?? 0) > 0 && (
                      <Badge tone="blue" title="当前匹配的进程数">{rule.matched_count} 个进程</Badge>
                    )}
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 text-xs text-muted-foreground">
                    <span className="truncate font-mono">{rule.process_name}</span>
                    <span>·</span>
                    <span className="shrink-0">{groupName.get(rule.proxy_group_id) ?? '默认'}</span>
                    <span>·</span>
                    <span className="shrink-0">进程树</span>
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100 focus-within:opacity-100">
                  <Button size="icon" variant="ghost" title="编辑规则" aria-label="编辑规则" onClick={() => onEdit(rule)}><Pencil /></Button>
                  <Button
                    size="icon"
                    variant="ghost"
                    title="删除规则"
                    aria-label="删除规则"
                    className="hover:text-destructive"
                    onClick={() => setPendingDelete({ ids: [rule.id], label: rule.name || rule.id })}
                  >
                    <Trash2 />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <Dialog
        open={pendingDelete != null}
        onOpenChange={o => { if (!o) setPendingDelete(null) }}
        title="删除规则"
        description={<>确定删除 <strong>{pendingDelete?.label}</strong> 吗？删除后无法撤销。</>}
        className="max-w-sm"
        footer={<>
          <Button onClick={() => setPendingDelete(null)}>取消</Button>
          <Button variant="danger" onClick={confirmDelete}>删除</Button>
        </>}
      />
    </div>
  )
}
