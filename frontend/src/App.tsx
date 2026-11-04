import * as Tabs from '@radix-ui/react-tabs'
import { useQuery } from '@tanstack/react-query'
import { Copy, Minus, Moon, Settings, Square, Sun, Waypoints, Wifi, ListChecks, X } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { Toaster } from 'sonner'
import { useDeleteRules, useSaveRule, type RulePayload } from '@/api/mutations'
import { getConnected, postReady, subscribeConnected } from '@/api/notify'
import { processDetailQuery, statsQuery, useProcessTree } from '@/api/queries'
import type { AutoRule, ProcessInfo } from '@/api/types'
import appIcon from '@/assets/proxyclaw-icon.png'
import { AutoRules } from '@/components/AutoRules'
import { ConfigEditor } from '@/components/ConfigEditor'
import { NetworkActivities } from '@/components/NetworkActivities'
import { ProcessContextHeader } from '@/components/ProcessContextHeader'
import { ProcessTree } from '@/components/ProcessTree'
import { ProxiesTab } from '@/components/ProxiesTab'
import { RuleEditorDialog } from '@/components/RuleEditorDialog'
import { Split } from '@/components/ui/split'
import { TooltipProvider } from '@/components/ui/tooltip'
import { useDocumentVisibility } from '@/hooks/useDocumentVisibility'
import { toggleTheme, useIsDark } from '@/hooks/useTheme'
import { dirOf, exeFromCmdline, findInTree } from '@/lib/process'
import { pushError } from '@/lib/toast'
import { cn } from '@/lib/utils'
import { PROXYCLAW_VERSION } from '@/version'

type TabKey = 'network' | 'rules' | 'proxies' | 'settings'
const TABS: { key: TabKey; label: string; icon: typeof Wifi }[] = [
  { key: 'network', label: '网络活动', icon: Wifi },
  { key: 'rules', label: '规则', icon: ListChecks },
  { key: 'proxies', label: '代理', icon: Waypoints },
  { key: 'settings', label: '设置', icon: Settings },
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

interface RuleDialogState { open: boolean; rule: AutoRule | null; name: string; dir: string }

export default function App() {
  const dark = useIsDark()
  const maximized = useMaximized()
  const connected = useSyncExternalStore(subscribeConnected, getConnected)
  const visible = useDocumentVisibility()
  const [tab, setTab] = useState<TabKey>('network')
  const [selectedPid, setSelectedPid] = useState<number | undefined>(undefined)
  const [ruleDialog, setRuleDialog] = useState<RuleDialogState>({ open: false, rule: null, name: '', dir: '' })

  const { data: stats } = useQuery(statsQuery)
  const tree = useProcessTree()
  const { data: detail } = useQuery(processDetailQuery(selectedPid))

  // When the window becomes visible again, ask the backend to replay the
  // latest snapshot: mutations pushed while hidden were dropped host-side.
  const wasVisible = useRef(visible)
  useEffect(() => {
    if (visible && !wasVisible.current) postReady()
    wasVisible.current = visible
  }, [visible])

  // Dynamic fields (hijacked, hijack_source, name) come from the pushed
  // tree; static fields (cmdline, image_path) from the one-shot detail query.
  const selectedProcess = useMemo<ProcessInfo | null>(() => {
    if (selectedPid == null) return null
    const live = findInTree(tree, selectedPid)
    if (!live) return null
    return detail && detail.pid === selectedPid
      ? { ...live, cmdline: detail.cmdline, image_path: detail.image_path }
      : live
  }, [tree, selectedPid, detail])

  const saveRule = useSaveRule()
  const deleteRules = useDeleteRules()

  const openRuleDialog = (rule: AutoRule | null, name = '', dir = '') =>
    setRuleDialog({ open: true, rule, name, dir })

  const onCreateRuleFromProcess = () => {
    if (!selectedProcess) return
    openRuleDialog(null, selectedProcess.name, dirOf(exeFromCmdline(selectedProcess.cmdline ?? '')))
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

  return (
    <TooltipProvider delayDuration={300}>
      <div className="flex h-screen w-full flex-col overflow-hidden bg-background text-foreground">
        <header className="titlebar flex h-10 shrink-0 select-none items-center justify-between border-b border-border">
          <div className="no-drag flex items-center gap-2 pl-4">
            <img src={appIcon} className="size-5 object-contain" alt="ProxyClaw" />
            <span className="text-sm font-semibold">ProxyClaw</span>
            <span className="text-xs text-muted-foreground">v{PROXYCLAW_VERSION}</span>
          </div>
          <div className="no-drag flex h-full items-center text-muted-foreground [&>button]:h-full [&>button]:px-3 [&>button]:transition-colors">
            <button type="button" onClick={toggleTheme} title="切换主题" className="hover:bg-muted hover:text-foreground">
              {dark ? <Moon className="size-3.5" /> : <Sun className="size-3.5" />}
            </button>
            <button type="button" onClick={() => windowCmd('minimize')} title="最小化" className="hover:bg-muted hover:text-foreground">
              <Minus className="size-3.5" />
            </button>
            <button type="button" onClick={() => windowCmd('maximize')} title="最大化 / 还原" className="hover:bg-muted hover:text-foreground">
              {maximized ? <Copy className="size-3" /> : <Square className="size-3" />}
            </button>
            <button type="button" onClick={() => windowCmd('close')} title="关闭" className="hover:bg-red-500 hover:text-white">
              <X className="size-3.5" />
            </button>
          </div>
        </header>

        <Split
          left={<ProcessTree selectedPid={selectedPid} onSelect={setSelectedPid} />}
          right={
            <Tabs.Root value={tab} onValueChange={v => setTab(v as TabKey)} className="flex min-h-0 flex-1 flex-col bg-background">
              <Tabs.List aria-label="主导航" className="flex shrink-0 items-center gap-1 px-5 pt-3 pb-3">
                {TABS.map(({ key, label, icon: Icon }) => (
                  <Tabs.Trigger
                    key={key}
                    value={key}
                    className={cn(
                      'flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm text-muted-foreground transition-colors',
                      'hover:text-foreground data-[state=active]:bg-card data-[state=active]:text-foreground data-[state=active]:shadow-sm',
                    )}
                  >
                    <Icon className="size-4" />
                    {label}
                    {key === 'rules' && rulesCount > 0 && (
                      <span className="rounded-full bg-muted px-1.5 text-[11px] font-medium text-muted-foreground">{rulesCount}</span>
                    )}
                  </Tabs.Trigger>
                ))}
              </Tabs.List>

              <Tabs.Content value="network" className="flex min-h-0 flex-1 flex-col data-[state=inactive]:hidden">
                <ProcessContextHeader process={selectedProcess} onCreateRule={onCreateRuleFromProcess} />
                <NetworkActivities selectedPid={selectedPid} />
              </Tabs.Content>
              <Tabs.Content value="rules" className="flex min-h-0 flex-1 flex-col data-[state=inactive]:hidden">
                <AutoRules onAdd={() => openRuleDialog(null)} onEdit={r => openRuleDialog(r)} />
              </Tabs.Content>
              <Tabs.Content value="proxies" className="flex min-h-0 flex-1 flex-col data-[state=inactive]:hidden">
                <ProxiesTab />
              </Tabs.Content>
              <Tabs.Content value="settings" className="flex min-h-0 flex-1 flex-col data-[state=inactive]:hidden">
                <ConfigEditor />
              </Tabs.Content>
            </Tabs.Root>
          }
        />

        <footer className="flex h-7 shrink-0 select-none items-center justify-between border-t border-border px-4 text-[11px] text-muted-foreground">
          <span>监听端口 <span className="font-mono text-foreground/80">18080</span></span>
          <span className="flex items-center gap-1.5">
            <span className={cn('size-1.5 rounded-full', connected ? 'bg-emerald-500' : 'bg-red-500')} />
            {connected ? '已连接' : '未连接'}
          </span>
        </footer>
      </div>

      <RuleEditorDialog
        open={ruleDialog.open}
        onOpenChange={open => setRuleDialog(d => ({ ...d, open }))}
        rule={ruleDialog.rule}
        prefillName={ruleDialog.name}
        prefillDir={ruleDialog.dir}
        saving={saveRule.isPending}
        onSave={onSave}
        onDelete={onDelete}
      />
      <Toaster position="bottom-center" theme={dark ? 'dark' : 'light'} richColors={false} closeButton duration={5000} />
    </TooltipProvider>
  )
}
