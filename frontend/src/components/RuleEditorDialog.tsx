import { zodResolver } from '@hookform/resolvers/zod'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronRight, CircleHelp, Cpu, FolderOpen, Lock, Terminal, Trash2 } from 'lucide-react'
import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { Controller, useForm } from 'react-hook-form'
import * as z from 'zod/mini'
import { browseExe } from '@/api/client'
import type { RulePayload } from '@/api/mutations'
import { proxyGroupsQuery } from '@/api/queries'
import { queryKeys } from '@/api/queryKeys'
import type { AutoRule, ProxyGroup, ProxyTarget } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Dialog } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/misc'
import { Select } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Tooltip } from '@/components/ui/tooltip'
import { TagInput } from './TagInput'
import { cn } from '@/lib/utils'

const schema = z.object({
  name: z.string().check(z.trim(), z.minLength(1)),
  processName: z.string().check(z.trim(), z.minLength(1)),
  workDir: z.string(),
  useWorkDir: z.boolean(),
  cmdlinePattern: z.string(),
  protocol: z.enum(['tcp', 'udp', 'both']),
  /** Proxy group id as a string. Kept while a custom address is chosen. */
  group: z.string(),
  custom: z.boolean(),
  customHost: z.string(),
  excludeCidrs: z.array(z.string()),
  includePorts: z.array(z.string()),
  includeCidrs: z.array(z.string()),
  excludePorts: z.array(z.string()),
})
export type RuleForm = z.infer<typeof schema>

export function ruleToForm(rule: AutoRule | null, prefillName = '', prefillDir = ''): RuleForm {
  if (rule) {
    return {
      name: rule.name,
      processName: rule.process_name,
      workDir: rule.image_path_pattern || '',
      useWorkDir: !!rule.image_path_pattern,
      cmdlinePattern: rule.cmdline_pattern,
      protocol: rule.protocol || 'tcp',
      group: String(rule.proxy_group_id ?? 0),
      custom: false,
      customHost: '',
      excludeCidrs: [...rule.dst_filter.exclude_cidrs],
      includePorts: [...rule.dst_filter.include_ports],
      includeCidrs: [...(rule.dst_filter.include_cidrs ?? [])],
      excludePorts: [...(rule.dst_filter.exclude_ports ?? [])],
    }
  }
  return {
    name: prefillName ? `${prefillName} 的规则` : '',
    processName: prefillName,
    workDir: prefillDir,
    useWorkDir: !!prefillDir,
    cmdlinePattern: '',
    protocol: 'tcp',
    group: '0',
    custom: false,
    customHost: '',
    excludeCidrs: [],
    includePorts: [],
    includeCidrs: [],
    excludePorts: [],
  }
}

export function formToPayload(f: RuleForm, groups: ProxyGroup[], enabled: boolean): RulePayload {
  const custom = f.custom
  let proxy: ProxyTarget
  if (custom && f.customHost) {
    const [host, port] = f.customHost.split(':')
    proxy = { type: 'socks5', host: host || '127.0.0.1', port: Number.parseInt(port ?? '7890') || 7890 }
  } else {
    const g = groups.find(x => x.id === Number.parseInt(f.group))
    proxy = { type: g?.type ?? 'socks5', host: g?.host ?? '127.0.0.1', port: g?.port ?? 7890 }
  }
  return {
    name: f.name,
    enabled,
    process_name: f.processName,
    cmdline_pattern: f.cmdlinePattern,
    image_path_pattern: f.useWorkDir ? f.workDir : '',
    // v0.9.0+: always tree-mode; kept in the payload for schema compatibility.
    hack_tree: true,
    protocol: f.protocol,
    // With a custom address the last selected group id is still sent.
    proxy_group_id: Number.parseInt(f.group, 10),
    proxy,
    dst_filter: {
      exclude_cidrs: f.excludeCidrs,
      include_cidrs: f.includeCidrs,
      include_ports: f.includePorts,
      exclude_ports: f.excludePorts,
    },
  }
}

function Help({ children }: { children: ReactNode }) {
  return (
    <Tooltip content={children} side="right">
      <CircleHelp className="size-3.5 cursor-help text-muted-foreground" />
    </Tooltip>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-4">
      <h3 className="text-2xs font-semibold text-muted-foreground">{title}</h3>
      {children}
    </section>
  )
}

function GroupChip({ group }: { group: ProxyGroup }) {
  return (
    <span className="flex min-w-0 items-center gap-2">
      <span className="font-medium">{group.name}</span>
      <span className="tabular truncate text-xs text-muted-foreground">socks5://{group.host}:{group.port}</span>
    </span>
  )
}

export function RuleEditorDialog({ open, onOpenChange, rule, prefillName, prefillDir, saving, onSave, onDelete }: {
  open: boolean
  onOpenChange: (open: boolean) => void
  rule: AutoRule | null
  prefillName?: string
  prefillDir?: string
  saving?: boolean
  onSave: (payload: RulePayload) => void
  onDelete: (id: string) => void
}) {
  const ids = useId()
  const qc = useQueryClient()
  const { data: groups = [] } = useQuery(proxyGroupsQuery)
  const fileInput = useRef<HTMLInputElement>(null)
  const [advanced, setAdvanced] = useState(false)
  const [confirmingDelete, setConfirmingDelete] = useState(false)

  const form = useForm<RuleForm>({
    resolver: zodResolver(schema),
    defaultValues: ruleToForm(null),
    mode: 'onChange',
  })
  const { register, control, handleSubmit, reset, setValue, watch, formState } = form

  // Reset the form each time the dialog opens; refresh the group list.
  useEffect(() => {
    if (!open) return
    const values = ruleToForm(rule, prefillName, prefillDir)
    reset(values)
    setConfirmingDelete(false)
    setAdvanced(values.excludeCidrs.length + values.includePorts.length + values.includeCidrs.length + values.excludePorts.length > 0)
    void qc.invalidateQueries({ queryKey: queryKeys.proxyGroups })
  }, [open, rule, prefillName, prefillDir, reset, qc])

  const group = watch('group')
  const custom = watch('custom')
  const customHost = watch('customHost')
  const useWorkDir = watch('useWorkDir')
  const name = watch('name')
  const processName = watch('processName')
  const canSave = name.trim() !== '' && processName.trim() !== ''

  const onBrowse = async () => {
    try {
      const data = await browseExe()
      if (data.cancelled) return
      if (data.name) setValue('processName', data.name, { shouldValidate: true })
      if (data.dir) setValue('workDir', data.dir)
      // Only ever turn the path condition on, never off.
      setValue('useWorkDir', true)
    } catch {
      // Backend not available: fall back to the HTML picker (name only).
      fileInput.current?.click()
    }
  }

  const submit = handleSubmit(values => onSave(formToPayload(values, groups, rule?.enabled ?? false)))
  const selectedGroup = groups.find(g => String(g.id) === group)

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      modalLock
      title="自动规则编辑器"
      description="设置进程匹配条件和代理方式"
      className="max-w-2xl"
      footer={<>
        {rule && (
          <div className="mr-auto flex items-center gap-2">
            {confirmingDelete ? (
              <>
                <Button size="sm" variant="danger" onClick={() => { setConfirmingDelete(false); onDelete(rule.id) }}>确认删除</Button>
                <Button size="sm" variant="ghost" onClick={() => setConfirmingDelete(false)}>取消</Button>
              </>
            ) : (
              <Button size="sm" variant="ghost" className="text-destructive hover:text-destructive" onClick={() => setConfirmingDelete(true)}>
                <Trash2 /> 删除规则
              </Button>
            )}
          </div>
        )}
        <Button onClick={() => onOpenChange(false)}>取消</Button>
        <Button variant="primary" disabled={!canSave || saving || !formState.isValid} onClick={() => void submit()}>
          {saving ? '正在保存…' : '保存规则'}
        </Button>
      </>}
    >
      <form className="space-y-7" onSubmit={e => { e.preventDefault(); void submit() }}>
        <Section title="基本信息">
          <div className="space-y-1.5">
            <Label htmlFor={`${ids}-name`} hint={<Help>规则的显示名称，仅用于识别。</Help>}>规则名称</Label>
            <Input id={`${ids}-name`} {...register('name')} />
          </div>
        </Section>

        <Section title="进程匹配">
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <Label htmlFor={`${ids}-proc`} hint={<Help>匹配可执行文件名，不区分大小写。支持通配符：* 匹配任意内容，? 匹配单个字符。</Help>}>进程名称</Label>
              <span className="text-xs text-muted-foreground">支持通配符（*）</span>
            </div>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Cpu className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input id={`${ids}-proc`} className="pl-8" {...register('processName')} />
              </div>
              <Button size="sm" onClick={onBrowse}><FolderOpen /> 浏览</Button>
              <input
                ref={fileInput}
                type="file"
                accept=".exe"
                className="hidden"
                onChange={e => {
                  const file = e.target.files?.[0]
                  if (file) {
                    setValue('processName', file.name, { shouldValidate: true })
                    // The HTML picker can't provide a full path.
                    setValue('workDir', '')
                    setValue('useWorkDir', true)
                  }
                  e.target.value = ''
                }}
              />
            </div>
            <div className={cn('flex h-control items-center gap-2 rounded-md bg-muted pl-2.5 pr-1.5', !useWorkDir && 'opacity-60')}>
              <Lock className="size-3.5 shrink-0 text-muted-foreground" />
              <input
                readOnly
                aria-label="程序所在目录"
                className="min-w-0 flex-1 select-all bg-transparent text-xs text-muted-foreground outline-none"
                placeholder="选择程序后自动填写"
                {...register('workDir')}
              />
              <span className="text-xs text-muted-foreground">作为匹配条件</span>
              <Controller
                control={control}
                name="useWorkDir"
                render={({ field }) => <Switch checked={field.value} onCheckedChange={field.onChange} aria-label="目录作为匹配条件" />}
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <Label htmlFor={`${ids}-cmd`} hint={<Help>选填。无通配符时，所有空格分隔的关键词都须出现，顺序不限；使用 * 或 ? 时，匹配完整命令行。</Help>}>命令行匹配</Label>
              <span className="text-xs text-muted-foreground">关键词或通配符</span>
            </div>
            <div className="relative">
              <Terminal className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                id={`${ids}-cmd`}
                className="pl-8"
                {...register('cmdlinePattern', {
                  onChange: e => { if ((e.target as HTMLInputElement).value) setValue('useWorkDir', true) },
                })}
              />
            </div>
          </div>

          <div className="flex items-start justify-between gap-4 rounded-lg bg-muted px-3 py-2.5 opacity-70">
            <div>
              <div className="text-sm font-medium">代理整个进程树</div>
              <div className="text-xs text-muted-foreground">v0.9.0 起始终包含子进程，暂不支持单进程模式。</div>
            </div>
            <Switch checked disabled aria-label="代理整个进程树" />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor={`${ids}-protocol`}>协议</Label>
            <Controller
              control={control}
              name="protocol"
              render={({ field }) => (
                <Select
                  id={`${ids}-protocol`}
                  value={field.value}
                  onValueChange={field.onChange}
                  options={[
                    { value: 'tcp', label: '仅 TCP' },
                    { value: 'udp', label: '仅 UDP' },
                    { value: 'both', label: 'TCP + UDP' },
                  ]}
                />
              )}
            />
            <p className="text-xs text-muted-foreground">选择本条规则需要代理的网络协议。</p>
          </div>
        </Section>

        <Section title="目标代理">
          <div className="space-y-1.5">
            <Label htmlFor={`${ids}-group`} hint={<Help>匹配的流量将通过所选 SOCKS5 代理组转发，可在“代理”页配置。</Help>}>代理组</Label>
            <Controller
              control={control}
              name="group"
              render={({ field }) => (
                <Select
                  id={`${ids}-group`}
                  value={custom ? 'custom' : field.value}
                  onValueChange={v => {
                    if (v === 'custom') setValue('custom', true)
                    else { setValue('custom', false); field.onChange(v) }
                  }}
                  display={custom
                    ? <span className="flex items-center gap-2"><span className="font-medium">自定义</span><span className="tabular text-xs text-muted-foreground">{customHost || '—'}</span></span>
                    : selectedGroup ? <GroupChip group={selectedGroup} /> : <span className="text-muted-foreground">选择代理组…</span>}
                  options={[
                    ...groups.map(g => ({ value: String(g.id), label: <GroupChip group={g} /> })),
                    { value: 'custom', label: <span className="flex items-center gap-2"><span className="font-medium">自定义</span><span className="text-xs text-muted-foreground">手动输入地址…</span></span> },
                  ]}
                />
              )}
            />
            {custom && (
              <div className="flex overflow-hidden rounded-lg border border-border focus-within:border-ring/60 focus-within:ring-2 focus-within:ring-ring/20">
                <span className="flex items-center bg-muted px-3 text-xs text-muted-foreground">socks5://</span>
                <input
                  className="tabular flex-1 bg-input px-3 py-1.5 text-xs outline-none"
                  spellCheck={false}
                  autoComplete="off"
                  placeholder="127.0.0.1:7890"
                  aria-label="自定义代理地址"
                  {...register('customHost')}
                />
              </div>
            )}
          </div>

          <div>
            <button
              type="button"
              className="flex items-center gap-1 text-xs font-medium text-primary"
              onClick={() => setAdvanced(v => !v)}
              aria-expanded={advanced}
            >
              <ChevronRight className={cn('size-4 transition-transform', advanced && 'rotate-90')} />
              高级设置
            </button>
            {advanced && (
              <div className="mt-4 space-y-5 border-l-2 border-border pl-4">
                <TagField control={control} name="excludeCidrs" id={`${ids}-xc`} label="直连网段（CIDR）"
                  help="访问这些网段时使用直连。配置文件中的默认排除网段对所有规则生效。"
                  placeholder="例如 192.168.0.0/16（回车添加）" note="按回车或逗号添加，点击 × 删除。" />
                <TagField control={control} name="includePorts" id={`${ids}-ip`} label="代理端口"
                  help="仅代理这些目标端口，留空则代理所有端口。" placeholder="例如 443（回车添加）" />
                <TagField control={control} name="includeCidrs" id={`${ids}-ic`} label="仅代理网段（CIDR）"
                  help="只代理访问这些网段的流量，其余直连。留空则不限制。" placeholder="例如 203.0.113.0/24（回车添加）" />
                <TagField control={control} name="excludePorts" id={`${ids}-xp`} label="直连端口"
                  help="访问这些目标端口时直连，优先于代理端口。支持范围，如 6000-6100。" placeholder="例如 22（回车添加）" />
                <p className="text-xs text-muted-foreground">判定顺序：全局排除网段 → 直连网段 → 直连端口 → 仅代理网段 → 代理端口。TCP 与 UDP 使用同一套判定。</p>
              </div>
            )}
          </div>
        </Section>
      </form>
    </Dialog>
  )
}

function TagField({ control, name, id, label, help, placeholder, note }: {
  control: ReturnType<typeof useForm<RuleForm>>['control']
  name: 'excludeCidrs' | 'includePorts' | 'includeCidrs' | 'excludePorts'
  id: string
  label: string
  help: string
  placeholder: string
  note?: string
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id} hint={<Help>{help}</Help>}>{label}</Label>
      <Controller
        control={control}
        name={name}
        render={({ field }) => <TagInput id={id} value={field.value} onChange={field.onChange} placeholder={placeholder} />}
      />
      {note && <p className="text-xs text-muted-foreground">{note}</p>}
    </div>
  )
}
