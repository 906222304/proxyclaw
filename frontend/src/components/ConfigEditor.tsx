import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Save, Upload } from 'lucide-react'
import { lazy, Suspense, useEffect, useId, useRef, useState } from 'react'
import { setAutostart, testProxyGroupIpv6, updateConfig, getConfig, UNSAFE_LOCATION_MESSAGE, type AutostartState } from '@/api/client'
import { autostartQuery, configQuery, dnsStatusQuery, statsQuery } from '@/api/queries'
import { queryKeys } from '@/api/queryKeys'
import type { DnsStatus, InterceptionStatus, Stats, WinDivertLayers } from '@/api/types'
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

const DNS_ERRORS: Record<string, string> = {
  proxy_unreachable: '代理不可用（UDP 与 TCP 都无法连到上游 DNS）',
  no_interface: '没有可用的网络接口',
  backup_failed: '无法备份系统 DNS，未做修改',
  set_failed: '修改系统 DNS 失败，已恢复',
  restore_failed: '恢复系统 DNS 失败，将在下次启动时重试',
  mode_unsupported: '不支持的模式',
}

/** Status line under the DNS switch; empty when there is nothing to show. */
export function dnsStatusText(s: DnsStatus | undefined): string {
  switch (s?.state) {
    case 'starting': return '启动中…'
    case 'stopping': return '正在关闭…'
    case 'running': return s.tcp_only ? '运行中（代理不支持 UDP，仅经 TCP 转发）' : '运行中'
    case 'failed': return `启动失败：${DNS_ERRORS[s.error ?? ''] ?? s.error ?? '未知错误'}`
    default: return ''
  }
}

/** Startup crash-recovery note for system DNS; empty when no recovery occurred. */
export function dnsRecoveryText(recovery: DnsStatus['recovery']): string {
  if (recovery === 'recovered') return '上次异常退出残留的系统 DNS 已在本次启动时自动恢复'
  if (recovery === 'failed') return '上次异常退出残留的系统 DNS 恢复失败，请检查网络适配器 DNS 设置或查看运行日志'
  return ''
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

const INTERCEPTION_LABEL: Record<string, string> = { windivert: 'WinDivert 驱动', hook: 'Hook 注入' }

const INTERCEPTION_ERRORS: Record<string, string> = {
  windivert_driver_failed: 'WinDivert 驱动加载失败，流量未被拦截（请确认以管理员权限运行、驱动文件完整且未被安全软件拦截）',
  windivert_socket_failed: 'WinDivert TCP 套接字层启动失败，流量未被拦截，详见运行日志',
  windivert_network_failed: 'WinDivert TCP 网络层启动失败，流量未被拦截，详见运行日志',
  hook_start_failed: 'Hook 注入引擎启动失败，流量未被拦截，详见运行日志',
}

/** Human-readable error message when interception fails to activate. */
export function interceptionErrorText(error?: string, mode?: string): string {
  if (error && INTERCEPTION_ERRORS[error]) return INTERCEPTION_ERRORS[error]
  const label = INTERCEPTION_LABEL[mode ?? ''] ?? '拦截引擎'
  return `${label}启动失败，流量未被拦截，详见运行日志`
}

/** Status under the interception select: pending restart, or a failed start. */
export function interceptionStatusText(saved: string, running?: InterceptionStatus): string {
  if (!running) return ''
  if (running.mode !== saved) return `重启 ProxyClaw 后生效（当前：${INTERCEPTION_LABEL[running.mode] ?? running.mode}）`
  if (!running.active) return interceptionErrorText(running.error, running.mode)
  return ''
}

/** Export filename with local YYYYMMDD date stamp. */
export function buildConfigFilename(now = new Date()): string {
  const y = now.getFullYear()
  const m = String(now.getMonth() + 1).padStart(2, '0')
  const d = String(now.getDate()).padStart(2, '0')
  return `proxyclaw-config-${y}${m}${d}.json`
}

/** Validate raw JSON text imported as a ProxyClaw configuration object. */
export function parseImportedConfig(text: string): Config {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new Error('JSON 格式无效')
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('配置文件必须是 JSON 对象')
  }
  return parsed as Config
}

const LAYER_LABELS: { key: keyof WinDivertLayers; label: string }[] = [
  { key: 'tcp_socket', label: 'TCP Socket' },
  { key: 'tcp_network', label: 'TCP Net' },
  { key: 'tcp_v6', label: 'IPv6' },
  { key: 'udp_socket', label: 'UDP Socket' },
  { key: 'udp_network', label: 'UDP Net' },
]

const stringify = (c: Config | undefined) => (c ? JSON.stringify(c, null, 2) : '')

export function ConfigEditor() {
  const qc = useQueryClient()
  const ids = useId()
  const { data: config } = useQuery(configQuery)
  const { data: autostart = { enabled: false, start_minimized: false } } = useQuery(autostartQuery)
  const { data: dnsStatus } = useQuery(dnsStatusQuery)
  const { data: stats } = useQuery(statsQuery)
  const effectiveDns = dnsStatus ?? stats?.dns
  const dnsText = dnsStatusText(effectiveDns)

  const ui = (config?.ui ?? {}) as Obj
  const dns = (config?.dns ?? {}) as Obj
  const closeToTray = (ui.close_to_tray as boolean | undefined) ?? true
  const dnsEnabled = !!dns.enabled
  const dnsMode = (dns.mode as string) || 'forwarder'
  const logLevel = (config?.log_level as string | undefined) ?? 'info'
  const interceptionMode = ((config?.interception as Obj | undefined)?.mode as string | undefined) === 'hook' ? 'hook' : 'windivert'
  const interceptionText = interceptionStatusText(interceptionMode, stats?.interception)
  const ipv6Raw = (config?.ipv6 as Obj | undefined)?.mode as string | undefined
  const ipv6Mode = ipv6Raw === 'direct' || ipv6Raw === 'proxy' ? ipv6Raw : 'block'

  // IPv6 egress check of the default proxy (shown in proxy mode only).
  const v6Probe = useMutation({ mutationFn: () => testProxyGroupIpv6(0) })
  const v6ProbeText = v6Probe.isPending ? '检测中…'
    : v6Probe.isError ? `检测失败：${errorText(v6Probe.error)}`
    : !v6Probe.data ? ''
    : v6Probe.data.ipv6_available ? `可用（${v6Probe.data.total_ms ?? 0} ms）`
    : `不可用：${v6Probe.data.error ?? '未知错误'}${v6Probe.data.failed_stage === 'remote' || v6Probe.data.failed_stage === 'first_byte' ? '。已暂时阻断该代理的 IPv6，应用回落 IPv4' : ''}`

  // Draft for the upstream text box; committed on change (blur / Enter).
  const savedUpstream = (dns.upstream_host as string) || ''
  const [upstreamDraft, setUpstreamDraft] = useState<string | null>(null)
  const upstreamValue = upstreamDraft ?? savedUpstream

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
    mutationFn: (next: Pick<AutostartState, 'enabled' | 'start_minimized'>) => setAutostart(next),
    onMutate: async (next) => {
      const prev = qc.getQueryData<AutostartState>(queryKeys.autostart)
      qc.setQueryData(queryKeys.autostart, { ...prev, ...next })
      return { prev }
    },
    onSuccess: (result) => qc.setQueryData(queryKeys.autostart, result),
    onError: (e, _n, ctx) => {
      if (ctx?.prev) qc.setQueryData(queryKeys.autostart, ctx.prev)
      pushError(e, '更新开机启动设置失败')
    },
  })
  // Autostart starts ProxyClaw elevated without a UAC prompt, so the backend
  // only allows it from a folder non-administrators cannot modify.
  const locationUnsafe = autostart.location_trusted === false
  const taskUnsafe = autostart.enabled && autostart.task_trusted === false
  const canEnableAutostart = autostart.enabled || !locationUnsafe

  const saveDns = (enabled = dnsEnabled, mode = dnsMode, upstream = upstreamValue) =>
    patch.mutate({ fn: dnsPatch(enabled, mode, upstream), ok: 'DNS 设置已保存', fail: '保存 DNS 设置失败' }, {
      // The backend applies DNS in the background; pick up "starting" now.
      onSuccess: () => { void qc.invalidateQueries({ queryKey: queryKeys.dnsStatus }) },
    })

  return (
    <div className="thin-scrollbar min-h-0 flex-1 overflow-auto">
      <div className="mx-auto flex w-full max-w-2xl flex-col gap-5 px-4 pt-3 pb-6">
        <EngineStatusCard stats={stats} dns={effectiveDns} />

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
              hint="以管理员权限、无 UAC 提示启动，因此仅允许从只有管理员能修改的文件夹（如 C:\Program Files\ProxyClaw）开启。移动 proxyclaw.exe 后，请重新开启此选项。"
            >
              <Switch
                checked={autostart.enabled}
                disabled={!canEnableAutostart}
                aria-label="登录 Windows 后自动启动"
                onCheckedChange={v => autostartMut.mutate({ enabled: v, start_minimized: autostart.start_minimized })}
              />
            </Row>
            {(taskUnsafe || (locationUnsafe && !autostart.enabled)) && (
              <div role="alert" data-testid="autostart-unsafe" className="space-y-1 bg-warning-soft py-2 pr-4 pl-9 text-2xs text-warning">
                <p className="font-medium">
                  {taskUnsafe
                    ? '已有的开机启动任务从普通用户可修改的文件夹以管理员权限启动 ProxyClaw，存在提权风险。建议关闭此选项，将 ProxyClaw 移到 C:\\Program Files 下后再开启。'
                    : UNSAFE_LOCATION_MESSAGE}
                </p>
                <p className="break-all opacity-80">{taskUnsafe ? autostart.task_issue : autostart.location_issue}</p>
              </div>
            )}
            <Row
              className="pl-9"
              title={<span className="text-xs font-normal">启动时隐藏到托盘</span>}
              description={autostart.enabled ? '自动启动时仅显示托盘图标。' : '需先开启“登录 Windows 后自动启动”。'}
            >
              <Switch
                checked={autostart.start_minimized}
                disabled={!autostart.enabled || locationUnsafe}
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
              title="拦截方式"
              description="如何接管被代理进程的连接。重启后生效。"
              hint="WinDivert 驱动：内核层拦截，覆盖 TCP 与 UDP，进程启动后的第一个连接也能接管。Hook 注入：不加载驱动，把 DLL 注入被代理的进程，在用户态改写 TCP 连接；子进程在启动前注入，已在运行的进程约 1 秒内注入，注入前的连接直连。Hook 模式下 UDP 直连，32 位进程、沙盒进程和只加载微软签名模块的进程不会被注入。"
            >
              <div className="flex items-center gap-3">
                {interceptionText && (
                  <span
                    data-testid="interception-status"
                    role="status"
                    className={stats?.interception?.active === false && stats.interception.mode === interceptionMode ? 'text-xs text-destructive' : 'text-xs text-muted-foreground'}
                  >
                    {interceptionText}
                  </span>
                )}
                <Select
                  value={interceptionMode}
                  ariaLabel="拦截方式"
                  onValueChange={m => patch.mutate({ fn: c => { c.interception = { ...((c.interception as Obj | undefined) ?? {}), mode: m } }, ok: '拦截方式已保存，重启后生效', fail: '保存拦截方式失败' })}
                  className="w-auto"
                  options={[
                    { value: 'windivert', label: 'WinDivert 驱动' },
                    { value: 'hook', label: 'Hook 注入' },
                  ]}
                />
              </div>
            </Row>
            <Row
              title="DNS 代理"
              description="通过代理转发 DNS 查询。"
              hint="适用于系统 DNS 无法解析目标服务的情况。此模式会修改系统 DNS，影响整台电脑。"
            >
              <div className="flex items-center gap-3">
                {dnsText && (
                  <span
                    data-testid="dns-status"
                    role="status"
                    className={effectiveDns?.state === 'failed' ? 'text-xs text-destructive' : 'text-xs text-muted-foreground'}
                  >
                    {dnsText}
                  </span>
                )}
                <Switch checked={dnsEnabled} aria-label="DNS 代理" onCheckedChange={v => saveDns(v)} />
              </div>
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
                    value={upstreamValue}
                    onChange={e => setUpstreamDraft(e.target.value)}
                    onBlur={() => {
                      if (upstreamDraft !== null) {
                        if (upstreamDraft !== savedUpstream) saveDns(dnsEnabled, dnsMode, upstreamDraft)
                        setUpstreamDraft(null)
                      }
                    }}
                    onKeyDown={e => { if (e.key === 'Enter') e.currentTarget.blur() }}
                    placeholder="DNS 服务器地址"
                    className="tabular w-44"
                  />
                  <span className="tabular text-xs text-muted-foreground">:53</span>
                </div>
              </div>
            )}
            <Row
              title="IPv6"
              description="被代理进程的 IPv6 连接如何处理。"
              hint="阻断：IPv6 连接被拒绝，应用自动改走 IPv4 并经过代理。代理：IPv6 TCP 与 UDP 经 SOCKS5 出口；若代理无法访问 IPv6，会自动暂时阻断该代理的 IPv6（5 分钟后重试），应用回落 IPv4。直连：IPv6 绕过代理。局域网 IPv6 始终不受影响。"
            >
              <Select
                value={ipv6Mode}
                ariaLabel="IPv6"
                onValueChange={m => patch.mutate({ fn: c => { c.ipv6 = { ...((c.ipv6 as Obj | undefined) ?? {}), mode: m } }, ok: 'IPv6 设置已保存', fail: '保存 IPv6 设置失败' })}
                className="w-auto"
                options={[
                  { value: 'block', label: '阻断，回落 IPv4' },
                  { value: 'proxy', label: '代理' },
                  { value: 'direct', label: '直连' },
                ]}
              />
            </Row>
            {ipv6Mode === 'proxy' && (
              <Row title="检测代理 IPv6" description="经默认代理连接一个 IPv6 地址，确认代理能访问 IPv6。">
                <div className="flex items-center gap-3">
                  {v6ProbeText && <span data-testid="ipv6-probe-result" className="text-xs text-muted-foreground">{v6ProbeText}</span>}
                  <Button size="sm" disabled={v6Probe.isPending} onClick={() => v6Probe.mutate()}>检测</Button>
                </div>
              </Row>
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

function EngineStatusCard({ stats, dns }: { stats: Stats | undefined; dns: DnsStatus | undefined }) {
  const ic = stats?.interception
  const icModeLabel = ic ? (INTERCEPTION_LABEL[ic.mode] ?? ic.mode) : '加载中…'
  const icFailed = ic != null && !ic.active
  const degradedLayers = ic?.active && ic.layers
    ? LAYER_LABELS.filter(l => !ic.layers![l.key]).map(l => l.label)
    : []

  const recoveryMsg = dnsRecoveryText(dns?.recovery)
  const dnsBadge = !dns || dns.state === 'off'
    ? { tone: 'neutral' as const, label: '未启用' }
    : dns.state === 'running'
      ? { tone: 'green' as const, label: dns.tcp_only ? '运行中 · 仅 TCP' : '运行中' }
      : dns.state === 'failed'
        ? { tone: 'red' as const, label: '启动失败' }
        : { tone: 'amber' as const, label: dns.state === 'starting' ? '启动中' : '关闭中' }

  const decisions = stats?.decisions
  const lateProxied = stats?.tcp_syn_parking?.socket?.late_rejected_proxied ?? 0
  const watchdogRel = stats?.tcp_syn_parking?.parking?.released_by_watchdog ?? 0
  const poolExhausted = stats?.tcp_syn_parking?.parking?.pool_exhausted ?? 0
  const anomalyParts: string[] = []
  if (lateProxied > 0) anomalyParts.push(`超时放行 ${lateProxied}`)
  if (watchdogRel > 0) anomalyParts.push(`看门狗释放 ${watchdogRel}`)
  if (poolExhausted > 0) anomalyParts.push(`缓冲池满 ${poolExhausted}`)

  const decisionDesc = decisions
    ? `已记录 ${decisions.written} 条（容量 ${decisions.capacity}`
      + (decisions.dropped > 0 ? `，丢弃 ${decisions.dropped} 条` : '')
      + '）'
      + (anomalyParts.length > 0 ? ` · 异常：${anomalyParts.join(' / ')}` : '')
    : '等待引擎上报…'

  return (
    <section data-testid="engine-status-card">
      <SectionTitle>引擎状态</SectionTitle>
      <Card className="divide-y divide-divider">
        <Row
          title="拦截引擎"
          description={ic ? `当前模式：${icModeLabel}${degradedLayers.length > 0 ? `（部分层未启用：${degradedLayers.join('、')}）` : ''}` : '正在读取引擎状态…'}
        >
          <Badge tone={ic == null ? 'neutral' : ic.active ? (degradedLayers.length > 0 ? 'amber' : 'green') : 'red'}>
            {ic == null ? '读取中' : ic.active ? (degradedLayers.length > 0 ? '部分运行' : '运行中') : '启动失败'}
          </Badge>
        </Row>
        {icFailed && (
          <div role="alert" data-testid="engine-interception-error" className="space-y-1.5 bg-destructive-soft px-4 py-2.5 text-2xs text-destructive">
            <p className="font-medium">{interceptionErrorText(ic.error, ic.mode)}</p>
            {ic.layers && (
              <div className="flex flex-wrap gap-1.5">
                {LAYER_LABELS.map(l => (
                  <Badge key={l.key} tone={ic.layers![l.key] ? 'green' : 'red'}>
                    {l.label}: {ic.layers![l.key] ? 'OK' : '失败'}
                  </Badge>
                ))}
              </div>
            )}
          </div>
        )}
        <Row
          title="进程树 (ETW)"
          description={stats
            ? (stats.tree_ready
              ? `共 ${stats.process_count ?? 0} 个运行中进程，已接管 ${stats.hijacked_pids} 个`
              : '正在同步系统进程列表…')
            : '正在读取进程树状态…'}
        >
          <Badge tone={stats == null ? 'neutral' : stats.tree_ready ? 'green' : 'amber'}>
            {stats == null ? '读取中' : stats.tree_ready ? '就绪' : '同步中'}
          </Badge>
        </Row>
        <Row
          title="DNS 与恢复"
          description={dns?.state === 'failed'
            ? dnsStatusText(dns)
            : dns?.state === 'running' && dns.listen
              ? `监听 ${dns.listen}${dns.tcp_only ? '（仅经 TCP 转发）' : ''}`
              : '系统 DNS 代理与异常退出自动恢复状态'}
        >
          <Badge tone={dnsBadge.tone}>{dnsBadge.label}</Badge>
        </Row>
        {recoveryMsg && (
          <div
            role={dns?.recovery === 'failed' ? 'alert' : 'status'}
            data-testid={`dns-recovery-${dns?.recovery}`}
            className={dns?.recovery === 'failed'
              ? 'bg-destructive-soft px-4 py-2 text-2xs font-medium text-destructive'
              : 'bg-info-soft px-4 py-2 text-2xs text-info'}
          >
            {recoveryMsg}
          </div>
        )}
        <Row
          title="决策记录"
          description={decisionDesc}
          hint="记录每条 TCP/UDP 连接在建立时的代理或直连决策，供“网络”页展示原因。"
        >
          {decisions ? (
            <Badge
              data-testid="decision-counts"
              tone={decisions.dropped > 0 || anomalyParts.length > 0 ? 'amber' : 'neutral'}
              className="tabular"
            >
              {decisions.written} / {decisions.capacity}
            </Badge>
          ) : (
            <Badge tone="neutral">—</Badge>
          )}
        </Row>
      </Card>
    </section>
  )
}

function RawConfig({ config }: { config: Config | undefined }) {
  const qc = useQueryClient()
  const dark = useIsDark()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [open, setOpen] = useState(false)
  // null means no local edits: follow server-side changes (e.g. a toggle above
  // rewrote the file). Non-null preserves the user's unsaved edits.
  const [draft, setDraft] = useState<string | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null)
  const [exporting, setExporting] = useState(false)
  const baseline = stringify(config)
  const text = draft ?? baseline
  const dirty = open && draft !== null && draft !== baseline

  useEffect(() => {
    if (!message?.ok) return
    const t = setTimeout(() => setMessage(null), 3000)
    return () => clearTimeout(t)
  }, [message])

  const invalidateAllConfigQueries = () => {
    void qc.invalidateQueries({ queryKey: queryKeys.config })
    void qc.invalidateQueries({ queryKey: queryKeys.autoRules })
    void qc.invalidateQueries({ queryKey: queryKeys.proxyGroups })
    void qc.invalidateQueries({ queryKey: queryKeys.stats })
    void qc.invalidateQueries({ queryKey: queryKeys.dnsStatus })
  }

  const openEditor = async () => {
    setLoadError(null)
    setDraft(null)
    setOpen(true)
    try {
      await qc.fetchQuery({ ...configQuery, staleTime: 0 })
    } catch (e) {
      setLoadError(errorText(e) || '读取配置失败，请重试')
    }
  }

  const save = useMutation({
    mutationFn: async (content: string) => {
      const parsed = parseImportedConfig(content)
      await updateConfig(parsed)
      return parsed
    },
    onSuccess: (parsed) => {
      qc.setQueryData(queryKeys.config, parsed)
      setDraft(null)
      setMessage({ ok: true, text: '配置已保存并重新加载' })
      invalidateAllConfigQueries()
    },
    onError: e => setMessage({ ok: false, text: errorText(e) || '保存配置失败' }),
  })

  const importMut = useMutation({
    mutationFn: async (file: File) => {
      const raw = await file.text()
      const parsed = parseImportedConfig(raw)
      await updateConfig(parsed)
      return parsed
    },
    onSuccess: () => {
      setDraft(null)
      invalidateAllConfigQueries()
      pushSuccess('配置已导入并重新加载')
    },
    onError: e => pushError(e, '导入配置失败'),
  })

  const handleExport = async () => {
    if (exporting) return
    setExporting(true)
    try {
      const latest = await getConfig()
      const blob = new Blob([JSON.stringify(latest, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = buildConfigFilename()
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      pushSuccess('配置已导出')
    } catch (e) {
      pushError(e, '导出配置失败')
    } finally {
      setExporting(false)
    }
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    importMut.mutate(file)
  }

  const close = () => {
    if (dirty && !confirm('有尚未保存的修改，确定放弃吗？')) return
    setOpen(false)
    setDraft(null)
    setMessage(null)
  }
  const doSave = () => { if (!save.isPending) save.mutate(text) }

  if (!open) {
    return (
      <section>
        <SectionTitle>高级</SectionTitle>
        <Card className="divide-y divide-divider">
          <Row title="导入 / 导出配置" description="导出当前配置为 JSON，或导入配置文件（自动迁移旧版本配置）。">
            <input
              ref={fileInputRef}
              type="file"
              accept=".json,application/json"
              aria-label="选择配置文件"
              className="hidden"
              onChange={handleFileChange}
            />
            <Button size="sm" disabled={exporting} onClick={() => void handleExport()}>
              <Download /> {exporting ? '导出中…' : '导出'}
            </Button>
            <Button size="sm" disabled={importMut.isPending} onClick={() => fileInputRef.current?.click()}>
              <Upload /> {importMut.isPending ? '导入中…' : '导入'}
            </Button>
          </Row>
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
            <JsonEditor value={text} onChange={v => setDraft(v === baseline ? null : v)} onSave={doSave} dark={dark} />
          </Suspense>
        </Card>
      )}
    </section>
  )
}
