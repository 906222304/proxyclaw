import * as Tabs from '@radix-ui/react-tabs'
import { useQuery } from '@tanstack/react-query'
import { Copy, Minus, Moon, Square, Sun, X } from 'lucide-react'
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
import { ProcessTree } from '@/components/ProcessTree'
import { ProxiesTab } from '@/components/ProxiesTab'
import { RuleEditorDialog } from '@/components/RuleEditorDialog'
import { Split } from '@/components/ui/split'
import { Tooltip, TooltipProvider } from '@/components/ui/tooltip'
import { useDocumentVisibility } from '@/hooks/useDocumentVisibility'
import { toggleTheme, useIsDark } from '@/hooks/useTheme'
import { dirOf, exeFromCmdline, findInTree } from '@/lib/process'
import { pushError } from '@/lib/toast'
import { cn } from '@/lib/utils'

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
      <Tabs.Root
        value={tab}
        onValueChange={v => setTab(v as TabKey)}
        className="flex h-screen w-full flex-col overflow-hidden bg-background text-foreground"
      >
        {/* One 44px bar: brand, centred tabs, status + window controls. The
            whole bar drags the window; interactive parts opt out. */}
        <header className="titlebar flex h-11 shrink-0 items-center bg-background">
          <div className="flex min-w-0 flex-1 basis-0 items-center gap-2 pl-3.5">
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

          <div className="flex h-full min-w-0 flex-1 basis-0 items-center justify-end">
            <Tooltip content={connected ? '代理引擎已连接 · 监听端口 18080' : '未连接到代理引擎'} side="bottom">
              <span
                tabIndex={0}
                data-connected={connected}
                aria-label={connected ? '已连接' : '未连接'}
                className="no-drag mr-1 flex h-6 items-center gap-1.5 rounded-md px-2 text-2xs text-muted-foreground hover:bg-field"
              >
                <span className={cn('size-1.5 rounded-full', connected ? 'bg-success' : 'bg-destructive')} />
                <span className="tabular">18080</span>
              </span>
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

        <Tabs.Content value="network" className="view-in flex min-h-0 flex-1 flex-col data-[state=inactive]:hidden">
          <Split
            left={<ProcessTree selectedPid={selectedPid} onSelect={setSelectedPid} />}
            right={
              <div className="mx-auto flex min-h-0 w-full max-w-content flex-1 flex-col px-4">
                <NetworkActivities
                  selectedPid={selectedPid}
                  process={selectedProcess}
                  onCreateRule={onCreateRuleFromProcess}
                />
              </div>
            }
          />
        </Tabs.Content>
        <Tabs.Content value="rules" className="view-in mx-auto flex min-h-0 w-full max-w-content flex-1 flex-col px-4 data-[state=inactive]:hidden">
          <AutoRules onAdd={() => openRuleDialog(null)} onEdit={r => openRuleDialog(r)} />
        </Tabs.Content>
        <Tabs.Content value="proxies" className="view-in mx-auto flex min-h-0 w-full max-w-content flex-1 flex-col px-4 data-[state=inactive]:hidden">
          <ProxiesTab onEditRule={r => openRuleDialog(r)} />
        </Tabs.Content>
        <Tabs.Content value="settings" className="view-in flex min-h-0 flex-1 flex-col data-[state=inactive]:hidden">
          <ConfigEditor />
        </Tabs.Content>
      </Tabs.Root>

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
