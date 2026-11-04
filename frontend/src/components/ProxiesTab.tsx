import { useIsFetching, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, Globe, Loader2, Pencil, Plus, RefreshCw, Server, Trash2 } from 'lucide-react'
import { useEffect, useId, useMemo, useState } from 'react'
import { useForm } from 'react-hook-form'
import { createProxyGroup, deleteProxyGroup, migrateProxyGroup, updateProxyGroup } from '@/api/client'
import { autoRulesQuery, proxyGroupsQuery, proxyTestQuery } from '@/api/queries'
import { queryKeys } from '@/api/queryKeys'
import type { AutoRule, GroupInUseError, ProxyGroup, ProxyTestResult } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Dialog } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Badge, Card, EmptyState, Label } from '@/components/ui/misc'
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

export function ProxiesTab() {
  const qc = useQueryClient()
  const { data: groups = [] } = useQuery(proxyGroupsQuery)
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
      <div className="flex h-12 shrink-0 items-center gap-3 px-5">
        <SearchInput value={query} onChange={setQuery} placeholder="搜索代理组…" className="w-60" />
        <span className="ml-auto text-xs text-muted-foreground">{groups.length} 个代理组</span>
        <Button size="sm" disabled={testingAll || visible.length === 0} onClick={testAll}>
          {testingAll ? <Loader2 className="animate-spin" /> : <RefreshCw />} 全部测速
        </Button>
        <Button size="sm" variant="primary" onClick={() => setEditing('new')}><Plus /> 新建代理组</Button>
      </div>

      <div className="thin-scrollbar min-h-0 flex-1 space-y-3 overflow-auto px-5 pb-5">
        {visible.length === 0 && <EmptyState icon={<Server />} title="没有找到代理组。" />}
        {visible.map(g => (
          <GroupCard
            key={g.id}
            group={g}
            rules={rulesByGroup.get(g.id) ?? []}
            deleting={remove.isPending}
            onTest={() => void runTest(g.id)}
            onEdit={() => setEditing(g)}
            onDelete={() => remove.mutate(g)}
          />
        ))}
      </div>

      <GroupEditor editing={editing} onClose={() => setEditing(null)} onSaved={refresh} />
      <MigrateDialog conflict={conflict} groups={groups} onClose={() => setConflict(null)} onDone={refresh} />
    </div>
  )
}

function GroupCard({ group, rules, deleting, onTest, onEdit, onDelete }: {
  group: ProxyGroup
  rules: AutoRule[]
  deleting: boolean
  onTest: () => void
  onEdit: () => void
  onDelete: () => void
}) {
  const { data: result, isFetching } = useQuery(proxyTestQuery(group.id))
  const [expanded, setExpanded] = useState(false)
  const ok = result?.latency_ms != null

  return (
    <Card className="p-4">
      <div className="flex items-center gap-2">
        <span className="text-sm font-semibold">{group.name}</span>
        <Badge>SOCKS5</Badge>
        <Button size="icon" variant="ghost" aria-label="编辑代理组" title="编辑代理组" onClick={onEdit}><Pencil /></Button>
        {group.id !== 0 && (
          <Button size="icon" variant="ghost" aria-label="删除代理组" title="删除代理组" className="hover:text-destructive" disabled={deleting} onClick={onDelete}>
            <Trash2 />
          </Button>
        )}
        <span className="ml-auto text-xs text-muted-foreground">{rules.length} 条规则</span>
      </div>
      <div className="mt-1 font-mono text-xs text-muted-foreground">socks5://{group.host}:{group.port}</div>

      <div className="mt-3 flex items-center gap-2 border-t border-border pt-3">
        <Globe className="size-4 shrink-0 text-muted-foreground" />
        <span className="flex-1 truncate text-xs text-muted-foreground">{group.test_url}</span>
        {isFetching ? (
          <Loader2 className="size-4 shrink-0 animate-spin text-primary" />
        ) : result ? (
          <Tooltip content={testTooltip(result)}>
            <button
              type="button"
              onClick={onTest}
              className={cn(
                'shrink-0 rounded-md px-2 py-0.5 text-xs font-semibold transition-colors',
                ok ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400' : 'bg-red-500/10 text-red-600 dark:text-red-400',
              )}
            >
              {ok ? `${result.latency_ms}ms` : failedLabel(result)}
            </button>
          </Tooltip>
        ) : (
          <Button size="icon" variant="ghost" title="测试连通性" aria-label="测试连通性" onClick={onTest}><RefreshCw /></Button>
        )}
      </div>

      {!isFetching && result?.stages?.length ? (
        <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 pl-6 font-mono text-[11px] text-muted-foreground">
          {result.stages.map(st => <span key={st.name}>{stageLabel(st.name)} {st.ms}ms</span>)}
          {result.failed_stage && <span className="text-red-500">{failedLabel(result)}：{result.error}</span>}
        </div>
      ) : null}

      {rules.length > 0 && (
        <div className="mt-2">
          <button type="button" onClick={() => setExpanded(v => !v)} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
            <ChevronDown className={cn('size-3 transition-transform', expanded && 'rotate-180')} />
            {expanded ? '收起' : '展开'}规则
          </button>
          {expanded && (
            <div className="mt-2 space-y-1 border-l-2 border-border pl-4">
              {rules.map(r => (
                <div key={r.id} className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span className="font-medium text-foreground">{r.name}</span>
                  <span className="font-mono">{r.process_name}</span>
                  {!r.enabled && <Badge className="h-4 text-[10px]">已停用</Badge>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </Card>
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
      <form className="space-y-4 pt-1" onSubmit={e => { e.preventDefault(); void submit() }}>
        <div className="space-y-1.5">
          <Label htmlFor={`${ids}-n`}>名称</Label>
          <Input id={`${ids}-n`} placeholder="我的代理" {...register('name')} />
        </div>
        <div className="flex gap-2">
          <div className="flex-1 space-y-1.5">
            <Label htmlFor={`${ids}-h`}>服务器地址</Label>
            <Input id={`${ids}-h`} placeholder="127.0.0.1" className="font-mono" {...register('host')} />
          </div>
          <div className="w-24 space-y-1.5">
            <Label htmlFor={`${ids}-p`}>端口</Label>
            <Input id={`${ids}-p`} placeholder="7890" inputMode="numeric" className="font-mono" {...register('port')} />
          </div>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor={`${ids}-u`}>测试网址</Label>
          <Input id={`${ids}-u`} placeholder="https://www.google.com" className="font-mono" {...register('test_url')} />
        </div>
        <button type="submit" hidden />
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
        <div className="space-y-3 pt-1">
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
