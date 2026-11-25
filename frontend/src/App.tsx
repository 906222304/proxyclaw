import * as Tabs from '@radix-ui/react-tabs'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Copy, Minus, Moon, Square, Sun, X } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { Toaster } from 'sonner'
import { useDeleteRules, useSaveRule, type RulePayload } from '@/api/mutations'
import { getConnected, postReady, subscribeConnected } from '@/api/notify'
import { processDetailQuery, statsQuery, useProcessTree } from '@/api/queries'
import type { AutoRule, ProcessInfo } from '@/api/types'
import appIcon from '@/assets/proxyclaw-icon.png'
import { AutoRules } from '@/components/AutoRules'
import { ConfigEditor, dnsRecoveryText, interceptionErrorText } from '@/components/ConfigEditor'
import { NetworkActivities } from '@/components/NetworkActivities'
import { ProcessTree } from '@/components/ProcessTree'
import { ProxiesTab } from '@/components/ProxiesTab'
import { RuleEditorDialog } from '@/components/RuleEditorDialog'
import { Split } from '@/components/ui/split'
import { Tooltip, TooltipProvider } from '@/components/ui/tooltip'
import { useDocumentVisibility } from '@/hooks/useDocumentVisibility'
import { toggleTheme, useIsDark } from '@/hooks/useTheme'
import { connectionToPrefill, processToPrefill, type RulePrefill } from '@/lib/presets'
import { findInTree } from '@/lib/process'
import { pushError } from '@/lib/toast'
import { cn } from '@/lib/utils'
import type { NetworkConnection } from '@/lib/connections'

type TabKey = 'network' | 'rules' | 'proxies' | 'settings'
const TABS: { key: TabKey; label: string }[] = [
  { key: 'network', label: '网络' },
  { key: 'rules', label: '规则' },
  { key: 'proxies', label: '代理' },
  { key: 'settings', label: '设置' },
]

function windowCmd(cmd: 'minimize' | 'maximize' | 'close') {
  window.chrome?.webview?.postMessage(cmd)
}

/** The host toggles `html.maximized` via execute_script. */
function useMaximized(): boolean {
  const [max, setMax] = useState(() => document.documentElement.classList.contains('maximized'))
  useEffect(() => {
    const el = document.documentElement
    const obs = new MutationObserver(() => setMax(el.classList.contains('maximized')))
    obs.observe(el, { attributes: true, attributeFilter: ['class'] })
    return () => obs.disconnect()
  }, [])
  return max
}

interface RuleDialogState { open: boolean; rule: AutoRule | null; prefill?: RulePrefill }

export default function App() {
  const qc = useQueryClient()
  const dark = useIsDark()
  const maximized = useMaximized()
  const connected = useSyncExternalStore(subscribeConnected, getConnected)
  const visible = useDocumentVisibility()
  const [tab, setTab] = useState<TabKey>('network')
  // The selection is one process, (pid, psn): when the PID is reused the
  // new process is not silently shown as the selected one.
  const [selected, setSelected] = useState<{ pid: number; psn: number } | undefined>(undefined)
  const [ruleDialog, setRuleDialog] = useState<RuleDialogState>({ open: false, rule: null })

  const { data: stats } = useQuery(statsQuery)
  const tree = useProcessTree()
  // A recycled PID (same pid, new psn) drops the selection; an exited one
  // keeps it so its last connections stay filtered.
  const selectedPid = useMemo(() => {
    if (!selected) return undefined
    const live = findInTree(tree, selected.pid)
    return live && live.psn !== selected.psn ? undefined : selected.pid
  }, [tree, selected])
  const { data: detail } = useQuery(processDetailQuery(selectedPid == null ? undefined : selected))
  const onSelectPid = (pid: number | undefined) => {
    const node = pid == null ? null : findInTree(tree, pid)
    setSelected(node ? { pid: node.pid, psn: node.psn } : undefined)
  }

  // When the window becomes visible again, ask the backend to replay the
  // latest snapshot: mutations pushed while hidden were dropped host-side.
  const wasVisible = useRef(visible)
  useEffect(() => {
    if (visible && !wasVisible.current) postReady()
    wasVisible.current = visible
  }, [visible])

  // Dynamic fields (hijacked, hijack_source, name) come from the pushed
  // tree; static fields (cmdline, image_path, package_family_name) from the one-shot detail query.
  const selectedProcess = useMemo<ProcessInfo | null>(() => {
    if (selected == null) return null
    const live = findInTree(tree, selected.pid)
    if (!live || live.psn !== selected.psn) return null
    return detail && detail.pid === live.pid && detail.psn === live.psn
      ? { ...live, cmdline: detail.cmdline, image_path: detail.image_path, package_family_name: detail.package_family_name }
      : live
  }, [tree, selected, detail])

  const saveRule = useSaveRule()
  const deleteRules = useDeleteRules()

  const openRuleDialog = (rule: AutoRule | null, prefill?: RulePrefill) =>
    setRuleDialog({ open: true, rule, prefill })

  const fetchDetailSafe = async (pid: number, psn: number): Promise<ProcessInfo | null> => {
    try {
      return await qc.fetchQuery(processDetailQuery({ pid, psn }))
    } catch {
      return null
    }
  }

  const openRuleForProcess = async (proc: ProcessInfo) => {
    setSelected({ pid: proc.pid, psn: proc.psn })
    let resolved: Pick<ProcessInfo, 'image_path' | 'cmdline' | 'package_family_name'> = proc
    if (!proc.image_path && !proc.cmdline && !proc.package_family_name) {
      const d = await fetchDetailSafe(proc.pid, proc.psn)
      if (d) resolved = d
    }
    openRuleDialog(null, processToPrefill(proc.name, resolved))
  }

  const openRuleForConnection = async (conn: NetworkConnection) => {
    const live = findInTree(tree, conn.pid)
    const psn = conn.decision?.psn && conn.decision.psn > 0 ? conn.decision.psn : live?.psn
    const resolved = live && psn != null && live.psn === psn
      ? await fetchDetailSafe(live.pid, live.psn)
      : null
    openRuleDialog(null, connectionToPrefill(conn, resolved))
  }

  const onCreateRuleFromProcess = () => {
    if (!selectedProcess) return
    void openRuleForProcess(selectedProcess)
  }

  const onSave = (payload: RulePayload) => {
    saveRule.mutate({ id: ruleDialog.rule?.id, payload }, {
      onSuccess: () => setRuleDialog(d => ({ ...d, open: false })),
      onError: e => pushError(e, '保存规则失败'),
    })
  }
  const onDelete = (id: string) => {
    deleteRules.mutate([id], {
      onSuccess: () => setRuleDialog(d => ({ ...d, open: false })),
      onError: e => pushError(e, '删除规则失败'),
    })
  }

  const rulesCount = stats?.auto_rules_count ?? 0
  const interceptionFailed = connected && stats?.interception?.active === false
  const dnsRecoveryFailed = connected && stats?.dns?.recovery === 'failed'
  const engineBanner = interceptionFailed
    ? interceptionErrorText(stats?.interception?.error, stats?.interception?.mode)
    : dnsRecoveryFailed
      ? dnsRecoveryText('failed')
      : ''
  const statusTooltip = !connected
    ? '未连接到代理引擎'
    : interceptionFailed
      ? engineBanner
      : dnsRecoveryFailed
        ? engineBanner
        : '代理引擎已连接 · 监听端口 18080'

  return (
    <TooltipProvider delayDuration={300}>
      <Tabs.Root
        value={tab}
        onValueChange={v => setTab(v as TabKey)}
        className="flex h-screen w-full flex-col overflow-hidden bg-background text-foreground"
      >
        {/* One 44px bar: brand, centred tabs, status + window controls. The
            whole bar drags the window; interactive parts opt out. */}
        <header className="titlebar flex h-11 shrink-0 items-center bg-background">
          <div className="aa-gray flex min-w-0 flex-1 basis-0 items-center gap-2 pl-3.5">
            <img src={appIcon} className="size-4.5 object-contain" alt="" />
            <span className="truncate text-xs font-semibold">ProxyClaw</span>
          </div>

          {/* aa-gray: own transparent layer -> grayscale AA, no ClearType fringes on CJK */}
          <Tabs.List aria-label="主导航" className="aa-gray no-drag flex shrink-0 items-center gap-0.5">
            {TABS.map(({ key, label }) => (
              <Tabs.Trigger
                key={key}
                value={key}
                className={cn(
                  'flex h-7 items-center gap-1.5 rounded-md px-3 text-xs text-muted-foreground transition-[background-color,color,box-shadow,scale] duration-150 active:scale-97',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30',
                  'data-[state=inactive]:hover:bg-field data-[state=inactive]:hover:text-foreground-2',
                  'data-[state=active]:bg-card data-[state=active]:font-medium data-[state=active]:text-foreground data-[state=active]:shadow-sm dark:data-[state=active]:bg-hover',
                )}
              >
                {label}
                {key === 'rules' && rulesCount > 0 && (
                  <span className="tabular text-2xs font-normal text-faint">{rulesCount}</span>
                )}
              </Tabs.Trigger>
            ))}
          </Tabs.List>

          <div className="aa-gray flex h-full min-w-0 flex-1 basis-0 items-center justify-end">
            <Tooltip content={statusTooltip} side="bottom">
              <button
                type="button"
                data-connected={connected}
                aria-label={!connected ? '未连接' : interceptionFailed ? '拦截引擎异常' : '已连接'}
                onClick={() => setTab('settings')}
                className="no-drag mr-1 flex h-6 items-center gap-1.5 rounded-md px-2 text-2xs text-muted-foreground hover:bg-field"
              >
                <span className={cn(
                  'size-1.5 rounded-full',
                  !connected || interceptionFailed ? 'bg-destructive' : dnsRecoveryFailed ? 'bg-warning' : 'bg-success',
                )}
                />
                <span className="tabular">18080</span>
              </button>
            </Tooltip>
            <div className="no-drag flex h-full items-center text-muted-foreground [&>button]:inline-flex [&>button]:h-full [&>button]:w-11 [&>button]:items-center [&>button]:justify-center [&>button]:transition-colors [&>button]:duration-150">
              <button type="button" onClick={toggleTheme} title="切换主题" className="hover:bg-field hover:text-foreground">
                {dark ? <Moon className="size-3.5" /> : <Sun className="size-3.5" />}
              </button>
              <button type="button" onClick={() => windowCmd('minimize')} title="最小化" className="hover:bg-field hover:text-foreground">
                <Minus className="size-3.5" />
              </button>
              <button type="button" onClick={() => windowCmd('maximize')} title="最大化 / 还原" className="hover:bg-field hover:text-foreground">
                {maximized ? <Copy className="size-3" /> : <Square className="size-3" />}
              </button>
              <button type="button" onClick={() => windowCmd('close')} title="关闭" className="hover:bg-titlebar-close hover:text-white">
                <X className="size-3.5" />
              </button>
            </div>
          </div>
        </header>

        {engineBanner && (
          <div
            role="alert"
            data-testid="engine-alert-banner"
            className="aa-gray flex shrink-0 items-center justify-between gap-3 border-b border-destructive/20 bg-destructive-soft px-4 py-1.5 text-xs text-destructive"
          >
            <span className="flex min-w-0 items-center gap-2">
              <AlertTriangle className="size-3.5 shrink-0" />
              <span className="truncate font-medium">{engineBanner}</span>
            </span>
            {tab !== 'settings' && (
              <button
                type="button"
                onClick={() => setTab('settings')}
                className="shrink-0 rounded px-2 py-0.5 text-2xs font-medium underline underline-offset-2 hover:bg-destructive/10"
              >
                查看引擎状态
              </button>
            )}
          </div>
        )}

        {/* aa-gray on each (transparent) panel: grayscale AA for all page text */}
        <Tabs.Content value="network" className="aa-gray view-in flex min-h-0 flex-1 flex-col data-[state=inactive]:hidden">
          <Split
            left={
              <ProcessTree
                selectedPid={selectedPid}
                onSelect={onSelectPid}
                onQuickCreateRule={proc => void openRuleForProcess(proc)}
              />
            }
            right={
              <div className="mx-auto flex min-h-0 w-full max-w-content flex-1 flex-col px-4">
                <NetworkActivities
                  selectedPid={selectedPid}
                  process={selectedProcess}
                  onCreateRule={onCreateRuleFromProcess}
                  onCreateRuleFromConnection={conn => void openRuleForConnection(conn)}
                />
              </div>
            }
          />
        </Tabs.Content>
        <Tabs.Content value="rules" className="aa-gray view-in mx-auto flex min-h-0 w-full max-w-content flex-1 flex-col px-4 data-[state=inactive]:hidden">
          <AutoRules
            onAdd={() => openRuleDialog(null)}
            onEdit={r => openRuleDialog(r)}
            onEditPreset={p => openRuleDialog(null, p)}
          />
        </Tabs.Content>
        <Tabs.Content value="proxies" className="aa-gray view-in mx-auto flex min-h-0 w-full max-w-content flex-1 flex-col px-4 data-[state=inactive]:hidden">
          <ProxiesTab onEditRule={r => openRuleDialog(r)} />
        </Tabs.Content>
        <Tabs.Content value="settings" className="aa-gray view-in flex min-h-0 flex-1 flex-col data-[state=inactive]:hidden">
          <ConfigEditor />
        </Tabs.Content>
      </Tabs.Root>

      <RuleEditorDialog
        open={ruleDialog.open}
        onOpenChange={open => setRuleDialog(d => ({ ...d, open }))}
        rule={ruleDialog.rule}
        prefill={ruleDialog.prefill}
        saving={saveRule.isPending}
        onSave={onSave}
        onDelete={onDelete}
      />
      <Toaster position="bottom-center" theme={dark ? 'dark' : 'light'} richColors={false} closeButton duration={5000} />
    </TooltipProvider>
  )
}
