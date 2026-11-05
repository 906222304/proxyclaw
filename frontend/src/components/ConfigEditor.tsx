import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Save } from 'lucide-react'
import { lazy, Suspense, useEffect, useId, useRef, useState } from 'react'
import { setAutostart, updateConfig, getConfig, type AutostartState } from '@/api/client'
import { autostartQuery, configQuery } from '@/api/queries'
import { queryKeys } from '@/api/queryKeys'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge, Card, Row, SectionTitle } from '@/components/ui/misc'
import { Select } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { useIsDark } from '@/hooks/useTheme'
import { pushError, pushSuccess } from '@/lib/toast'
import { errorText } from '@/lib/utils'
import { PROXYCLAW_VERSION } from '@/version'
import { LogViewer } from './LogViewer'

const JsonEditor = lazy(() => import('./JsonEditor'))

type Config = Record<string, unknown>
type Obj = Record<string, unknown>

/** Read-modify-write against the latest server config. */
export function patchConfig(config: Config, patch: (c: Config) => void): Config {
  const next = structuredClone(config)
  patch(next)
  return next
}

export function dnsPatch(enabled: boolean, mode: string, upstream: string) {
  return (c: Config) => {
    const dns = { ...((c.dns ?? {}) as Obj) }
    dns.enabled = enabled
    dns.mode = mode
    dns.upstream_host = upstream
    dns.upstream_port = 53
    if (!dns.listen_host) dns.listen_host = '127.0.0.2'
    if (!dns.listen_port) dns.listen_port = 53
    c.dns = dns
  }
}

const stringify = (c: Config | undefined) => (c ? JSON.stringify(c, null, 2) : '')

export function ConfigEditor() {
  const qc = useQueryClient()
  const ids = useId()
  const { data: config } = useQuery(configQuery)
  const { data: autostart = { enabled: false, start_minimized: false } } = useQuery(autostartQuery)

  const ui = (config?.ui ?? {}) as Obj
  const dns = (config?.dns ?? {}) as Obj
  const closeToTray = (ui.close_to_tray as boolean | undefined) ?? true
  const dnsEnabled = !!dns.enabled
  const dnsMode = (dns.mode as string) || 'forwarder'
  const logLevel = (config?.log_level as string | undefined) ?? 'info'

  // Draft for the upstream text box; committed on change (blur / Enter).
  const [upstreamDraft, setUpstreamDraft] = useState('')
  useEffect(() => { setUpstreamDraft((dns.upstream_host as string) || '') }, [dns.upstream_host])

  /** Fetch the latest config, apply `patch`, PUT it, refresh the cache. */
  const patch = useMutation({
    mutationFn: async ({ fn }: { fn: (c: Config) => void; ok?: string; fail: string }) => {
      const latest = await getConfig()
      const next = patchConfig(latest, fn)
      await updateConfig(next)
      return next
    },
    onMutate: async ({ fn }) => {
      await qc.cancelQueries({ queryKey: queryKeys.config })
      const prev = qc.getQueryData<Config>(queryKeys.config)
      if (prev) qc.setQueryData(queryKeys.config, patchConfig(prev, fn))
      return { prev }
    },
    onSuccess: (_d, { ok }) => { if (ok) pushSuccess(ok) },
    onError: (e, { fail }, ctx) => {
      if (ctx?.prev) qc.setQueryData(queryKeys.config, ctx.prev)
      pushError(e, fail)
    },
    onSettled: () => qc.invalidateQueries({ queryKey: queryKeys.config }),
  })

  const autostartMut = useMutation({
    mutationFn: (next: AutostartState) => setAutostart(next),
    onMutate: async (next) => {
      const prev = qc.getQueryData<AutostartState>(queryKeys.autostart)
      qc.setQueryData(queryKeys.autostart, next)
      return { prev }
    },
    onSuccess: (result) => qc.setQueryData(queryKeys.autostart, result),
    onError: (e, _n, ctx) => {
      if (ctx?.prev) qc.setQueryData(queryKeys.autostart, ctx.prev)
      pushError(e, '更新开机启动设置失败')
    },
  })

  const saveDns = (enabled = dnsEnabled, mode = dnsMode, upstream = upstreamDraft) =>
    patch.mutate({ fn: dnsPatch(enabled, mode, upstream), ok: 'DNS 设置已保存', fail: '保存 DNS 设置失败' })

  return (
    <div className="thin-scrollbar min-h-0 flex-1 overflow-auto">
      <div className="mx-auto flex w-full max-w-2xl flex-col gap-5 px-4 pt-2 pb-6">
        <section>
          <SectionTitle>通用</SectionTitle>
          <Card className="divide-y divide-divider">
            <Row
              title="关闭窗口后保持后台运行"
              description="关闭窗口后代理继续运行，可从托盘重新打开。"
              hint="默认开启。点击托盘图标重新打开窗口，右键选择“退出 ProxyClaw”结束运行。设置立即生效。"
            >
              <Switch
                checked={closeToTray}
                disabled={patch.isPending}
                aria-label="关闭窗口后保持后台运行"
                onCheckedChange={v => patch.mutate({
                  fn: c => { c.ui = { ...((c.ui ?? {}) as Obj), close_to_tray: v } },
                  fail: '更新后台运行设置失败',
                })}
              />
            </Row>
            <Row
              title="登录 Windows 后自动启动"
              description="以管理员权限启动，无需每次确认。"
              hint="移动 proxyclaw.exe 后，请重新开启此选项。"
            >
              <Switch
                checked={autostart.enabled}
                aria-label="登录 Windows 后自动启动"
                onCheckedChange={v => autostartMut.mutate({ enabled: v, start_minimized: autostart.start_minimized })}
              />
            </Row>
            <Row
              className="pl-9"
              title={<span className="text-xs font-normal">启动时隐藏到托盘</span>}
              description={autostart.enabled ? '自动启动时仅显示托盘图标。' : '需先开启“登录 Windows 后自动启动”。'}
            >
              <Switch
                checked={autostart.start_minimized}
                disabled={!autostart.enabled}
                aria-label="启动时隐藏到托盘"
                onCheckedChange={v => autostartMut.mutate({ enabled: true, start_minimized: v })}
              />
            </Row>
          </Card>
        </section>

        <section>
          <SectionTitle>网络</SectionTitle>
          <Card className="divide-y divide-divider">
            <Row
              title="DNS 代理"
              description="通过代理转发 DNS 查询。"
              hint="适用于系统 DNS 无法解析目标服务的情况。此模式会修改系统 DNS，影响整台电脑。"
            >
              <Switch checked={dnsEnabled} aria-label="DNS 代理" onCheckedChange={v => saveDns(v)} />
            </Row>
            {dnsEnabled && (
              <div className="space-y-2.5 py-3 pr-4 pl-9">
                <div className="flex items-center gap-3">
                  <label htmlFor={`${ids}-mode`} className="w-20 shrink-0 text-2xs text-muted-foreground">模式</label>
                  <Select
                    id={`${ids}-mode`}
                    value={dnsMode}
                    onValueChange={m => saveDns(dnsEnabled, m)}
                    className="w-auto"
                    options={[{ value: 'forwarder', label: '全局转发（系统 DNS → 127.0.0.2）' }]}
                  />
                </div>
                <div className="flex items-center gap-3">
                  <label htmlFor={`${ids}-up`} className="w-20 shrink-0 text-2xs text-muted-foreground">上游服务器</label>
                  <Input
                    id={`${ids}-up`}
                    value={upstreamDraft}
                    onChange={e => setUpstreamDraft(e.target.value)}
                    onBlur={() => { if (upstreamDraft !== ((dns.upstream_host as string) || '')) saveDns() }}
                    onKeyDown={e => { if (e.key === 'Enter') e.currentTarget.blur() }}
                    placeholder="DNS 服务器地址"
                    className="tabular w-44"
                  />
                  <span className="tabular text-xs text-muted-foreground">:53</span>
                </div>
              </div>
            )}
          </Card>
        </section>

        <section>
          <SectionTitle>诊断</SectionTitle>
          <Card className="divide-y divide-divider">
            <Row title="日志级别" description="修改后立即生效。" hint="调试模式会记录更多连接细节。">
              <Select
                value={logLevel}
                onValueChange={lvl => patch.mutate({ fn: c => { c.log_level = lvl }, ok: '日志级别已保存', fail: '保存日志级别失败' })}
                className="w-24"
                options={[
                  { value: 'debug', label: '调试' },
                  { value: 'info', label: '信息' },
                  { value: 'warning', label: '警告' },
                  { value: 'error', label: '错误' },
                ]}
              />
            </Row>
            <Row title="运行日志" description="连接、掉线和错误记录，用于排查问题。">
              <LogViewer />
            </Row>
          </Card>
        </section>

        <RawConfig config={config} />

        <section>
          <SectionTitle>关于</SectionTitle>
          <Card className="space-y-1 px-4 py-3 text-2xs text-muted-foreground">
            <p><span className="text-sm font-medium text-foreground">ProxyClaw</span> <span className="tabular ml-1 text-foreground-2">v{PROXYCLAW_VERSION}</span></p>
            <p>
              ProxyClaw · Windows 进程级代理与分流 ·{' '}
              <a href="https://github.com/906222304/proxyclaw" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">本项目源码</a>
            </p>
          </Card>
        </section>
      </div>
    </div>
  )
}

function RawConfig({ config }: { config: Config | undefined }) {
  const qc = useQueryClient()
  const dark = useIsDark()
  const [open, setOpen] = useState(false)
  const [text, setText] = useState('')
  const [loadError, setLoadError] = useState<string | null>(null)
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null)
  const baseline = stringify(config)
  const lastBaseline = useRef(baseline)
  const dirty = open && text !== baseline

  // While there are no local edits, follow server-side changes (e.g. a
  // toggle above rewrote the file). With local edits, keep the user's work.
  useEffect(() => {
    if (open && text === lastBaseline.current) setText(baseline)
    lastBaseline.current = baseline
  }, [baseline])

  useEffect(() => {
    if (!message?.ok) return
    const t = setTimeout(() => setMessage(null), 3000)
    return () => clearTimeout(t)
  }, [message])

  const openEditor = async () => {
    setLoadError(null)
    setOpen(true)
    try {
      const fresh = await qc.fetchQuery({ ...configQuery, staleTime: 0 })
      const s = stringify(fresh)
      lastBaseline.current = s
      setText(s)
    } catch (e) {
      setLoadError(errorText(e) || '读取配置失败，请重试')
    }
  }

  const save = useMutation({
    mutationFn: async (content: string) => {
      let parsed: Config
      try {
        parsed = JSON.parse(content) as Config
      } catch {
        throw new Error('JSON 格式无效')
      }
      await updateConfig(parsed)
      return parsed
    },
    onSuccess: (parsed) => {
      const s = stringify(parsed)
      lastBaseline.current = s
      qc.setQueryData(queryKeys.config, parsed)
      setText(s)
      setMessage({ ok: true, text: '配置已保存并重新加载' })
      void qc.invalidateQueries({ queryKey: queryKeys.config })
    },
    onError: e => setMessage({ ok: false, text: errorText(e) || '保存配置失败' }),
  })

  const close = () => {
    if (dirty && !confirm('有尚未保存的修改，确定放弃吗？')) return
    setOpen(false)
    setMessage(null)
  }
  const doSave = () => { if (!save.isPending) save.mutate(text) }

  if (!open) {
    return (
      <section>
        <SectionTitle>高级</SectionTitle>
        <Card>
          <Row title="配置文件" description="直接编辑 JSON 配置。">
            <Button size="sm" onClick={() => void openEditor()}>编辑</Button>
          </Row>
        </Card>
      </section>
    )
  }

  return (
    <section className="flex flex-col">
      <div className="mb-2 flex items-center justify-between gap-3 px-1">
        <div className="flex items-center gap-2">
          <h2 className="text-2xs font-semibold text-muted-foreground">配置文件</h2>
          {dirty && <Badge tone="amber">尚未保存</Badge>}
          {message && <span className={message.ok ? 'text-xs text-success' : 'text-xs text-destructive'}>{message.text}</span>}
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="primary" disabled={save.isPending || loadError !== null || !dirty} onClick={doSave}>
            <Save /> {save.isPending ? '正在保存…' : '保存并重新加载'}
          </Button>
          <Button size="sm" onClick={close}>关闭</Button>
        </div>
      </div>
      {loadError ? (
        <div role="alert" className="flex items-center gap-3 px-1 text-sm text-destructive">
          {loadError}
          <Button size="sm" onClick={() => void openEditor()}>重试</Button>
        </div>
      ) : (
        <Card className="h-120 overflow-hidden">
          <Suspense fallback={<p role="status" className="p-4 text-sm text-muted-foreground">正在加载配置编辑器…</p>}>
            <JsonEditor value={text} onChange={setText} onSave={doSave} dark={dark} />
          </Suspense>
        </Card>
      )}
    </section>
  )
}
