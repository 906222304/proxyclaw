import { useIsFetching, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronRight, Globe, Loader2, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { useEffect, useId, useMemo, useState } from 'react'
import { useForm } from 'react-hook-form'
import { createProxyGroup, deleteProxyGroup, migrateProxyGroup, updateProxyGroup } from '@/api/client'
import { autoRulesQuery, proxyGroupsQuery, proxyTestQuery } from '@/api/queries'
import { queryKeys } from '@/api/queryKeys'
import type { AutoRule, GroupInUseError, ProxyGroup, ProxyTestResult } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Dialog } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { ProcessIcon } from '@/components/ProcessIcon'
import { EmptyState, Label, ListSkeleton } from '@/components/ui/misc'
import { MoreMenu } from '@/components/ui/menu'
import { SearchInput } from '@/components/ui/search-input'
import { Select } from '@/components/ui/select'
import { Tooltip } from '@/components/ui/tooltip'
import { pushError } from '@/lib/toast'
import { cn } from '@/lib/utils'

const STAGE_LABELS: Record<string, string> = {
  resolve: '解析代理地址',
  connect: '连接代理',
  handshake: 'SOCKS5 握手',
  remote: '代理连接目标',
  first_byte: '目标首字节',
  config: '测试网址',
  queue: '排队',
}
export const stageLabel = (name: string) => STAGE_LABELS[name] ?? name

/** Tooltip: one line per stage, then the outcome. */
export function testTooltip(r: ProxyTestResult): string {
  const lines = (r.stages ?? []).map(s => `${stageLabel(s.name)}：${s.ms} ms`)
  if (r.latency_ms != null) {
    lines.push(`合计 ${r.latency_ms} ms${r.detail ? `（${r.detail}）` : ''}`)
  } else {
    if (r.failed_stage) lines.push(`失败于：${stageLabel(r.failed_stage)}`)
    if (r.error) lines.push(r.error)
  }
  if (r.target) lines.push(`目标：${r.target}`)
  return lines.join('\n')
}

export const failedLabel = (r: ProxyTestResult) => (r.failed_stage ? `${stageLabel(r.failed_stage)}失败` : '连接失败')

interface GroupForm { name: string; host: string; port: string; test_url: string }
const EMPTY_FORM: GroupForm = { name: '', host: '127.0.0.1', port: '7890', test_url: 'https://www.google.com' }

export function ProxiesTab({ onEditRule }: { onEditRule?: (rule: AutoRule) => void } = {}) {
  const qc = useQueryClient()
  const { data: groups = [], isPending: loading } = useQuery(proxyGroupsQuery)
  const { data: rules = [] } = useQuery(autoRulesQuery)
  const [query, setQuery] = useState('')
  const [editing, setEditing] = useState<ProxyGroup | 'new' | null>(null)
  const [conflict, setConflict] = useState<{ group: ProxyGroup; info: GroupInUseError } | null>(null)
  const testingAll = useIsFetching({ queryKey: ['proxyTest'] }) > 0

  const visible = useMemo(() => {
    const q = query.toLowerCase().trim()
    return q ? groups.filter(g => g.name.toLowerCase().includes(q) || g.host.includes(q)) : groups
  }, [groups, query])

  const rulesByGroup = useMemo(() => {
    const m = new Map<number, AutoRule[]>()
    for (const r of rules) m.set(r.proxy_group_id, [...(m.get(r.proxy_group_id) ?? []), r])
    return m
  }, [rules])

  const refresh = () => Promise.all([
    qc.invalidateQueries({ queryKey: queryKeys.proxyGroups }),
    qc.invalidateQueries({ queryKey: queryKeys.autoRules }),
  ])

  const runTest = (id: number) => qc.fetchQuery({ ...proxyTestQuery(id), staleTime: 0 })
  // The backend runs at most 4 probes at once and queues the rest.
  const testAll = () => { void Promise.all(visible.map(g => runTest(g.id))) }

  const remove = useMutation({
    mutationFn: (g: ProxyGroup) => deleteProxyGroup(g.id),
    onSuccess: (result, g) => {
      if ('error' in result && result.error === 'group_in_use') setConflict({ group: g, info: result })
      else void refresh()
    },
    onError: e => pushError(e, '删除代理组失败'),
  })

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex h-12 shrink-0 items-center gap-3">
        <SearchInput value={query} onChange={setQuery} placeholder="搜索代理组…" className="w-56" />
        <span className="tabular ml-auto text-2xs text-muted-foreground">{groups.length} 个代理组</span>
        <Button size="sm" disabled={testingAll || visible.length === 0} onClick={testAll}>
          {testingAll ? <Loader2 className="animate-spin" /> : <RefreshCw />} 全部测速
        </Button>
        <Button size="sm" variant="primary" onClick={() => setEditing('new')}><Plus /> 新建代理组</Button>
      </div>

      <div className="thin-scrollbar min-h-0 flex-1 overflow-auto pb-4">
        {loading && <ListSkeleton rows={2} />}
        {!loading && visible.length === 0 && <EmptyState title="没有找到代理组" />}
        {visible.length > 0 && (
          <div className="divide-y divide-divider overflow-hidden rounded-xl border border-border bg-card">
        {visible.map(g => (
          <GroupRow
            key={g.id}
            group={g}
            rules={rulesByGroup.get(g.id) ?? []}
            deleting={remove.isPending}
            onTest={() => void runTest(g.id)}
            onEdit={() => setEditing(g)}
            onEditRule={onEditRule}
            onDelete={() => remove.mutate(g)}
          />
        ))}
          </div>
        )}
      </div>

      <GroupEditor editing={editing} onClose={() => setEditing(null)} onSaved={refresh} />
      <MigrateDialog conflict={conflict} groups={groups} onClose={() => setConflict(null)} onDone={refresh} />
    </div>
  )
}

const latencyTone = (ms: number) => (ms < 300 ? 'text-success' : ms < 1000 ? 'text-warning' : 'text-destructive')

/** 48px row; click expands an inline panel (test URL, last result, rules). */
function GroupRow({ group, rules, deleting, onTest, onEdit, onDelete, onEditRule }: {
  group: ProxyGroup
  rules: AutoRule[]
  onEditRule?: (rule: AutoRule) => void
  deleting: boolean
  onTest: () => void
  onEdit: () => void
  onDelete: () => void
}) {
  const { data: result, isFetching } = useQuery(proxyTestQuery(group.id))
  const [expanded, setExpanded] = useState(false)
  const ok = result?.latency_ms != null

  return (
    <div>
      <div
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        onClick={() => setExpanded(v => !v)}
        onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setExpanded(v => !v) } }}
        className={cn('flex min-h-12 items-center gap-3 py-1.5 pr-3 pl-4 outline-none transition-colors duration-100 hover:bg-surface-2 focus-visible:bg-surface-2', expanded && 'bg-surface-2')}
      >
        <ChevronRight className={cn('size-3.5 shrink-0 text-faint transition-transform', expanded && 'rotate-90')} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-medium">{group.name}</div>
          <div className="tabular truncate text-2xs text-muted-foreground">
            SOCKS5 · {group.host}:{group.port} · {rules.length} 条规则
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-1" onClick={e => e.stopPropagation()}>
          {result && !isFetching && (
            <Tooltip content={testTooltip(result)}>
              <span tabIndex={0} className={cn('tabular px-1 text-xs font-medium', ok ? latencyTone(result.latency_ms!) : 'text-destructive')}>
                {ok ? `${result.latency_ms} ms` : failedLabel(result)}
              </span>
            </Tooltip>
          )}
          <Button size="icon" variant="ghost" title="测试连通性" aria-label="测试连通性" disabled={isFetching} onClick={onTest}>
            {isFetching ? <Loader2 className="animate-spin text-primary" /> : <RefreshCw />}
          </Button>
          <MoreMenu items={[
            { label: '编辑代理组', icon: <Pencil />, onSelect: onEdit },
            ...(group.id !== 0 ? [{ label: '删除代理组', icon: <Trash2 />, danger: true, disabled: deleting, onSelect: onDelete }] : []),
          ]} />
        </div>
      </div>

      {expanded && (
        <div className="space-y-2 bg-surface-2 pt-1 pr-4 pb-3 pl-10.5 text-2xs text-muted-foreground">
          <div className="flex min-w-0 items-center gap-1.5">
            <Globe className="size-3 shrink-0 text-faint" />
            <span className="selectable truncate">{group.test_url}</span>
          </div>
          {!isFetching && result?.stages?.length ? (
            <div className="tabular flex flex-wrap gap-x-3 gap-y-0.5">
              {result.stages.map(st => <span key={st.name}>{stageLabel(st.name)} {st.ms} ms</span>)}
              {result.failed_stage && <span className="text-destructive">{failedLabel(result)}：{result.error}</span>}
            </div>
          ) : null}
          {rules.length > 0 ? (
            <div className="divide-y divide-divider overflow-hidden rounded-lg border border-divider bg-card" data-testid="group-rules">
              {rules.map(r => (
                <button
                  key={r.id}
                  type="button"
                  onClick={() => onEditRule?.(r)}
                  disabled={!onEditRule}
                  title={onEditRule ? '编辑规则' : undefined}
                  className="flex h-9 w-full min-w-0 items-center gap-2.5 px-3 text-left transition-colors duration-100 enabled:hover:bg-hover disabled:cursor-default"
                >
                  <ProcessIcon name={r.process_name} className={cn('size-4 shrink-0', !r.enabled && 'opacity-50 grayscale')} />
                  <span className={cn('min-w-0 shrink truncate text-xs font-medium', r.enabled ? 'text-foreground' : 'text-muted-foreground')}>{r.name}</span>
                  <span className="min-w-0 flex-1 truncate text-2xs text-muted-foreground">{r.process_name}</span>
                  <span className={cn('flex shrink-0 items-center gap-1.5 text-2xs', r.enabled ? 'text-muted-foreground' : 'text-faint')}>
                    <span className={cn('size-1.5 rounded-full', r.enabled ? 'bg-success' : 'bg-faint')} />
                    {r.enabled ? '已启用' : '已停用'}
                  </span>
                </button>
              ))}
            </div>
          ) : (
            <p>暂无规则使用此代理组</p>
          )}
        </div>
      )}
    </div>
  )
}

function GroupEditor({ editing, onClose, onSaved }: {
  editing: ProxyGroup | 'new' | null
  onClose: () => void
  onSaved: () => Promise<unknown>
}) {
  const ids = useId()
  const { register, reset, handleSubmit } = useForm<GroupForm>({ defaultValues: EMPTY_FORM })
  const existing = editing && editing !== 'new' ? editing : null

  useEffect(() => {
    if (!editing) return
    reset(editing === 'new'
      ? EMPTY_FORM
      : { name: editing.name, host: editing.host, port: String(editing.port), test_url: editing.test_url })
  }, [editing, reset])

  const save = useMutation({
    mutationFn: async (f: GroupForm) => {
      const data = {
        name: f.name,
        host: f.host,
        port: Number.parseInt(f.port, 10) || 7890,
        type: 'socks5' as const,
        test_url: f.test_url,
      }
      if (existing) await updateProxyGroup(existing.id, data)
      else await createProxyGroup(data)
    },
    onSuccess: async () => { onClose(); await onSaved() },
    onError: e => pushError(e, '保存代理组失败'),
  })
  const submit = handleSubmit(f => save.mutate(f))

  return (
    <Dialog
      open={editing != null}
      onOpenChange={o => { if (!o) onClose() }}
      modalLock
      title={existing ? '编辑代理组' : '新建代理组'}
      description="设置 SOCKS5 代理服务器。"
      footer={<>
        <Button onClick={onClose}>取消</Button>
        <Button variant="primary" disabled={save.isPending} onClick={() => void submit()}>
          {save.isPending ? '正在保存…' : existing ? '保存' : '创建'}
        </Button>
      </>}
    >
      <form className="space-y-4" onSubmit={e => { e.preventDefault(); void submit() }}>
        {/* first, not last: space-y adds margin below every child but the last */}
        <button type="submit" hidden />
        <div className="space-y-1.5">
          <Label htmlFor={`${ids}-n`}>名称</Label>
          <Input id={`${ids}-n`} placeholder="我的代理" {...register('name')} />
        </div>
        <div className="flex gap-2">
          <div className="flex-1 space-y-1.5">
            <Label htmlFor={`${ids}-h`}>服务器地址</Label>
            <Input id={`${ids}-h`} placeholder="127.0.0.1" className="tabular" {...register('host')} />
          </div>
          <div className="w-24 space-y-1.5">
            <Label htmlFor={`${ids}-p`}>端口</Label>
            <Input id={`${ids}-p`} placeholder="7890" inputMode="numeric" className="tabular" {...register('port')} />
          </div>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor={`${ids}-u`}>测试网址</Label>
          <Input id={`${ids}-u`} placeholder="https://www.google.com" className="tabular" {...register('test_url')} />
        </div>
      </form>
    </Dialog>
  )
}

function MigrateDialog({ conflict, groups, onClose, onDone }: {
  conflict: { group: ProxyGroup; info: GroupInUseError } | null
  groups: ProxyGroup[]
  onClose: () => void
  onDone: () => Promise<unknown>
}) {
  const id = useId()
  const [target, setTarget] = useState('0')
  useEffect(() => { if (conflict) setTarget('0') }, [conflict])

  const migrate = useMutation({
    mutationFn: () => migrateProxyGroup(conflict!.group.id, Number.parseInt(target, 10)),
    onSuccess: async () => { onClose(); await onDone() },
    onError: e => pushError(e, '迁移代理组失败'),
  })

  const info = conflict?.info
  return (
    <Dialog
      open={conflict != null}
      onOpenChange={o => { if (!o) onClose() }}
      modalLock
      title={`无法删除“${conflict?.group.name ?? ''}”`}
      description="此代理组仍在使用中，请将关联规则和手动代理迁移至其他代理组后再删除。"
      className="max-w-lg"
      footer={<>
        <Button onClick={onClose}>取消</Button>
        <Button variant="danger" disabled={migrate.isPending} onClick={() => migrate.mutate()}>
          {migrate.isPending ? '正在处理…' : '迁移并删除'}
        </Button>
      </>}
    >
      {info && (
        <div className="space-y-3">
          {info.auto_rules.length > 0 && (
            <div>
              <p className="mb-1 text-sm font-medium">自动规则（{info.auto_rules.length}）</p>
              <div className="space-y-1 border-l-2 border-border pl-3">
                {info.auto_rules.map(r => <div key={r.id} className="text-xs text-muted-foreground">{r.name}</div>)}
              </div>
            </div>
          )}
          {info.manual_hijack_count > 0 && (
            <p className="text-sm font-medium">手动代理：{info.manual_hijack_count} 个进程</p>
          )}
          <div className="space-y-1.5 border-t border-border pt-3">
            <Label htmlFor={id}>迁移至</Label>
            <Select
              id={id}
              value={target}
              onValueChange={setTarget}
              placeholder="选择目标代理组"
              options={groups.filter(g => g.id !== conflict?.group.id).map(g => ({
                value: String(g.id), label: `${g.name} (${g.host}:${g.port})`,
              }))}
            />
          </div>
        </div>
      )}
    </Dialog>
  )
}
