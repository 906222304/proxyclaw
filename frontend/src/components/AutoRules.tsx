import { useQuery } from '@tanstack/react-query'
import { Pencil, Plus, Power, PowerOff, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useDeleteRules, useSetRuleGroup, useSetRulesEnabled } from '@/api/mutations'
import { autoRulesQuery, proxyGroupsQuery } from '@/api/queries'
import type { AutoRule, ProxyGroup } from '@/api/types'
import { ProcessIcon } from '@/components/ProcessIcon'
import { MoreMenu } from '@/components/ui/menu'
import { Select } from '@/components/ui/select'
import { Button } from '@/components/ui/button'
import { Dialog } from '@/components/ui/dialog'
import { Checkbox, EmptyState, ListSkeleton, Segmented } from '@/components/ui/misc'
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
  const { data: rules = [], isPending: loading } = useQuery(autoRulesQuery)
  const { data: groups = [] } = useQuery(proxyGroupsQuery)

  const [query, setQuery] = useState('')
  const [status, setStatus] = useState<StatusFilter>('all')
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set())
  const [pendingDelete, setPendingDelete] = useState<{ ids: string[]; label: string } | null>(null)

  const setEnabled = useSetRulesEnabled()
  const setGroup = useSetRuleGroup()
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
  const changeGroup = (rule: AutoRule, id: string) => {
    const g = groups.find(x => String(x.id) === id)
    if (!g) return
    setGroup.mutate({ id: rule.id, group: g }, { onError: e => pushError(e, '切换代理组失败') })
  }
  const selecting = selected.size > 0
  const confirmDelete = () => {
    if (!pendingDelete) return
    const { ids } = pendingDelete
    setPendingDelete(null)
    setSelected(new Set())
    del.mutate(ids, { onError: e => pushError(e, '删除规则失败') })
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex h-12 shrink-0 items-center gap-3 pl-4 pr-0">
        <Checkbox checked={allSelected} indeterminate={someSelected} onChange={toggleAll} label="全选" />
        {selected.size === 0 ? (
          <>
            <SearchInput value={query} onChange={setQuery} placeholder="搜索规则…" className="w-56" />
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

      <div className="thin-scrollbar min-h-0 flex-1 overflow-auto pb-4">
        {loading ? (
          <ListSkeleton rows={3} />
        ) : visible.length === 0 ? (
          <EmptyState
            title={query || status !== 'all'
              ? '没有找到匹配的规则'
              : <>暂无规则，点击 <strong>添加规则</strong> 创建第一条规则</>}
          />
        ) : (
          <div className="divide-y divide-divider overflow-hidden rounded-xl border border-border bg-card">
            {visible.map(rule => (
              <RuleRow
                key={rule.id}
                rule={rule}
                groups={groups}
                selected={selected.has(rule.id)}
                selecting={selecting}
                onToggleSelect={() => toggleOne(rule.id)}
                onToggleEnabled={() => toggleRule(rule)}
                onGroup={id => changeGroup(rule, id)}
                onEdit={() => onEdit(rule)}
                onDelete={() => setPendingDelete({ ids: [rule.id], label: rule.name || rule.id })}
              />
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

const PROTOCOL_LABEL: Record<string, string> = { tcp: 'TCP', udp: 'UDP', both: 'TCP+UDP' }

/** Rule row: [hover checkbox] icon · name / sub-line · group select · switch · ⋯ */
function RuleRow({ rule, groups, selected, selecting, onToggleSelect, onToggleEnabled, onGroup, onEdit, onDelete }: {
  rule: AutoRule
  groups: ProxyGroup[]
  selected: boolean
  selecting: boolean
  onToggleSelect: () => void
  onToggleEnabled: () => void
  onGroup: (id: string) => void
  onEdit: () => void
  onDelete: () => void
}) {
  const group = groups.find(g => g.id === rule.proxy_group_id)
  // A rule saved with a custom address keeps its last group id; show it as 自定义.
  const custom = !!group && (rule.proxy.host !== group.host || rule.proxy.port !== group.port)
  const matched = rule.matched_count ?? 0
  const sub = [
    rule.process_name,
    '进程树',
    PROTOCOL_LABEL[rule.protocol ?? 'tcp'] ?? 'TCP',
    matched > 0 ? `${matched} 个进程` : null,
  ].filter(Boolean).join(' · ')

  return (
    <div
      onClick={onEdit}
      className={cn('group flex min-h-13 items-center gap-3 py-2 pr-3 pl-4 transition-colors duration-100', selected ? 'bg-selected' : 'hover:bg-surface-2')}
    >
      <span className={cn('flex w-3.5 shrink-0 justify-center transition-opacity', selecting || selected ? 'opacity-100' : 'opacity-0 group-hover:opacity-100 focus-within:opacity-100')}>
        <Checkbox checked={selected} onChange={onToggleSelect} label={`选择 ${rule.name}`} />
      </span>
      <ProcessIcon name={rule.process_name} className={cn('size-5', !rule.enabled && 'grayscale')} />
      <button type="button" aria-label={`编辑规则 ${rule.name}`} className="min-w-0 flex-1 text-left outline-none" onClick={e => { e.stopPropagation(); onEdit() }}>
        <div className={cn('truncate text-sm font-medium', !rule.enabled && 'text-muted-foreground')}>{rule.name}</div>
        <div className="truncate text-2xs text-muted-foreground" title={sub}>{sub}</div>
      </button>
      <div className="flex shrink-0 items-center gap-2" onClick={e => e.stopPropagation()}>
        <Select
          ariaLabel="代理组"
          value={String(rule.proxy_group_id)}
          onValueChange={onGroup}
          className="w-32"
          display={custom ? <span className="truncate">自定义</span> : undefined}
          options={groups.map(g => ({ value: String(g.id), label: g.name }))}
        />
        <Switch
          checked={rule.enabled}
          onCheckedChange={onToggleEnabled}
          aria-label={rule.enabled ? '停用规则' : '启用规则'}
        />
        <MoreMenu items={[
          { label: '编辑规则', icon: <Pencil />, onSelect: onEdit },
          { label: '删除规则', icon: <Trash2 />, danger: true, onSelect: onDelete },
        ]} />
      </div>
    </div>
  )
}
