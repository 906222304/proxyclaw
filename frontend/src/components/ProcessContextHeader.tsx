import { useQuery } from '@tanstack/react-query'
import { Check, ChevronDown, ChevronUp, CircleSlash, Copy, FolderOpen, Plus, Undo2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { revealFile } from '@/api/client'
import { useExcludeProcess, useRestoreProcess } from '@/api/mutations'
import { autoRulesQuery } from '@/api/queries'
import type { ProcessInfo } from '@/api/types'
import { Button } from '@/components/ui/button'
import { MoreMenu, type MenuItem } from '@/components/ui/menu'
import { Tooltip } from '@/components/ui/tooltip'
import { ProcessIcon } from '@/components/ProcessIcon'
import { excludeActionFor, hijackKind, type ExcludeAction } from '@/lib/exclusion'
import { dirOf, exeFromCmdline } from '@/lib/process'
import { pushError, pushSuccess } from '@/lib/toast'
import { cn } from '@/lib/utils'

/** Split a process into its directory, exe name and arguments. */
export function describeProcess(node: ProcessInfo) {
  const cmdline = node.cmdline ?? node.name ?? ''
  const exeName = node.name ?? ''
  const imagePath = node.image_path || exeFromCmdline(cmdline)
  const cwd = dirOf(node.image_path || exeFromCmdline(cmdline))
  let args = cmdline
  const prefixes = [`"${cwd}${exeName}"`, `${cwd}${exeName}`, `"${exeName}"`, exeName]
  const hit = prefixes.find(p => p && cmdline.startsWith(p))
  if (hit) args = cmdline.slice(hit.length).trimStart()
  else {
    const idx = exeName ? cmdline.indexOf(exeName) : -1
    if (idx !== -1) args = cmdline.slice(idx + exeName.length).trimStart()
  }
  return { cmdline, exeName, imagePath, cwd, args }
}

/**
 * Split a directory (with trailing separator) into a head that may ellipsize
 * and a tail (last folder plus separators) that always stays, so a truncated
 * path reads `D:\a\proxy…\win\proxyclaw.exe`.
 */
export function splitDir(cwd: string): { head: string, tail: string } {
  if (!cwd) return { head: '', tail: '' }
  const body = cwd.slice(0, -1)
  const sep = Math.max(body.lastIndexOf('\\'), body.lastIndexOf('/'))
  if (sep <= 0) return { head: '', tail: cwd }
  return { head: body.slice(0, sep), tail: cwd.slice(sep) }
}

/** Hijack source as a small dot; the tooltip names it. */
export function HijackDot({ source }: { source?: string | null }) {
  const kind = hijackKind(source)
  if (!kind) return null
  const label = kind === 'manual' ? '手动代理' : '自动代理（规则）'
  return (
    <Tooltip content={label}>
      <span aria-label={label} className={cn('size-1.5 shrink-0 rounded-full', kind === 'manual' ? 'bg-success' : 'bg-info')} />
    </Tooltip>
  )
}

/** Exclusion is runtime-only on the backend; say so wherever it is offered. */
export const EXCLUDE_HINT = '进程重启后恢复'
export const EXCLUDED_TOOLTIP = `已排除：此进程不走代理（${EXCLUDE_HINT}）`

/** Small muted "已排除" tag for a process excluded from its auto rule(s). */
export function ExcludedBadge({ className }: { className?: string }) {
  return (
    <Tooltip content={EXCLUDED_TOOLTIP}>
      <span data-testid="excluded-badge" className={cn('shrink-0 rounded border border-border px-1 text-2xs leading-4 text-muted-foreground', className)}>已排除</span>
    </Tooltip>
  )
}

/**
 * Tree-row variant: a hollow ring with the same tooltip, so deep rows keep
 * their name width.
 */
export function ExcludedDot() {
  return (
    <Tooltip content={EXCLUDED_TOOLTIP}>
      <span data-testid="excluded-dot" aria-label="已排除" className="size-1.5 shrink-0 rounded-full border border-muted-foreground" />
    </Tooltip>
  )
}

/** The ⋯ menu entries for the exclude / restore action (none when not applicable). */
export function excludeMenuItems(action: ExcludeAction | null, run: (a: ExcludeAction) => void, busy = false): MenuItem[] {
  if (!action) return []
  return action.kind === 'exclude'
    ? [{ label: '此进程不走代理', icon: <CircleSlash />, hint: EXCLUDE_HINT, title: `仅对此 PID 生效，不影响子进程；已建立的连接会保持到关闭。${EXCLUDE_HINT}`, onSelect: () => run(action), disabled: busy }]
    : [{ label: '恢复代理', icon: <Undo2 />, onSelect: () => run(action), disabled: busy }]
}

/**
 * 48px header row for the selected process: icon, name, sub-line
 * "PID · path args" (copy / reveal actions overlay the path end on hover,
 * taking no width otherwise), 创建规则, and a ⋯ menu with 此进程不走代理 /
 * 恢复代理 when an auto rule matches the process.
 * The path middle-truncates: the directory ellipsizes, the exe name stays,
 * arguments give way first. The expand chevron sits inline right after the path and shows the full
 * command line; copy / reveal actions follow on hover.
 */
export function ProcessContextHeader({ process, onCreateRule }: {
  process: ProcessInfo
  onCreateRule: () => void
}) {
  const [copied, setCopied] = useState<'cwd' | 'full' | null>(null)
  const [expanded, setExpanded] = useState(false)
  const [located, setLocated] = useState(false)

  useEffect(() => {
    if (!copied) return
    const t = setTimeout(() => setCopied(null), 1500)
    return () => clearTimeout(t)
  }, [copied])

  const { cmdline, exeName, imagePath, cwd, args } = describeProcess(process)
  const dir = splitDir(cwd)
  const isLong = args.length > 40 || cmdline.length > 60

  const copy = async (text: string, kind: 'cwd' | 'full') => {
    try { await navigator.clipboard.writeText(text) } catch { /* ignore */ }
    setCopied(kind)
  }
  const locate = async () => {
    const path = imagePath || cwd + exeName
    if (!path) return
    setLocated(true)
    try { await revealFile(path) } catch { /* ignore */ }
    setTimeout(() => setLocated(false), 1000)
  }
  const { data: rules } = useQuery(autoRulesQuery)
  const action = excludeActionFor(process, rules)
  const excludeMut = useExcludeProcess()
  const restoreMut = useRestoreProcess()
  const busy = excludeMut.isPending || restoreMut.isPending
  const runAction = (a: ExcludeAction) => {
    const vars = { pid: process.pid, ruleIds: a.ruleIds }
    if (a.kind === 'exclude') {
      excludeMut.mutate(vars, {
        onSuccess: () => pushSuccess(`${process.name} 已不走代理（${EXCLUDE_HINT}）`),
        onError: e => pushError(e, '排除进程失败'),
      })
    } else {
      restoreMut.mutate(vars, {
        onSuccess: () => pushSuccess(`${process.name} 已恢复代理`),
        onError: e => pushError(e, '恢复代理失败'),
      })
    }
  }
  const menuItems = excludeMenuItems(action, runAction, busy)

  const iconBtn = 'flex size-5 shrink-0 items-center justify-center rounded text-muted-foreground transition hover:bg-field hover:text-foreground'

  return (
    <div className="shrink-0">
      <div className="flex h-12 items-center gap-3">
        <ProcessIcon name={process.name} className="size-5.5" />
        <div className="group/path min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span className="truncate text-sm font-medium">{process.name}</span>
            <HijackDot source={process.hijack_source} />
            {action?.kind === 'restore' && <ExcludedBadge />}
          </div>
          <div className="relative flex min-w-0 items-center gap-1 text-2xs text-muted-foreground">
            <span className="tabular shrink-0">PID {process.pid}</span>
            {cmdline && (
              <>
                <span className="shrink-0 text-faint">·</span>
                <span className="selectable flex min-w-0 items-baseline" title={cmdline} data-testid="process-path">
                  {dir.head && <span className="min-w-0 truncate" data-testid="process-path-dir">{dir.head}</span>}
                  {dir.tail && <span className="shrink-0 whitespace-pre">{dir.tail}</span>}
                  <span className="shrink-0 text-foreground-2" data-testid="process-path-exe">{exeName}</span>
                  {args && <span className="min-w-0 shrink-[100] truncate pl-1">{args}</span>}
                </span>
                {isLong && (
                  <button type="button" onClick={() => setExpanded(v => !v)} title={expanded ? '收起命令行' : '展开完整命令行'} aria-expanded={expanded} data-testid="process-cmdline-toggle" className={iconBtn}>
                    {expanded ? <ChevronUp className="size-3" /> : <ChevronDown className="size-3" />}
                  </button>
                )}
                {/* Overlay: takes no width when hidden; fades over the path end on hover. */}
                <span className="pointer-events-none absolute inset-y-0 right-0 flex items-center bg-linear-to-r from-transparent via-background via-40% to-background pl-8 opacity-0 transition-opacity group-hover/path:pointer-events-auto group-hover/path:opacity-100 focus-within:pointer-events-auto focus-within:opacity-100">
                  <button type="button" onClick={locate} title="打开程序所在文件夹" className={cn(iconBtn, located && 'text-success')}>
                    <FolderOpen className="size-3" />
                  </button>
                  {cwd && (
                    <button type="button" onClick={() => copy(cwd, 'cwd')} title="复制工作目录" className={iconBtn}>
                      {copied === 'cwd' ? <Check className="size-3 text-success" /> : <Copy className="size-3" />}
                    </button>
                  )}
                  <button type="button" onClick={() => copy(cmdline, 'full')} title="复制完整命令行" className={cn(iconBtn, 'w-auto gap-0.5 px-1')}>
                    {copied === 'full' ? <Check className="size-3 text-success" /> : <><Copy className="size-3" /><span>全部</span></>}
                  </button>
                </span>
              </>
            )}
          </div>
        </div>
        <Button size="sm" variant="ghost" onClick={onCreateRule} title="为此进程创建规则">
          <Plus /> 创建规则
        </Button>
        {menuItems.length > 0 && <MoreMenu items={menuItems} label="进程操作" />}
      </div>
      {expanded && cmdline && (
        <p className="mb-2 break-all rounded-lg bg-surface-2 px-3 py-2 font-mono text-2xs text-muted-foreground">{cmdline}</p>
      )}
    </div>
  )
}
