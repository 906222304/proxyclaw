import { Check, ChevronDown, ChevronUp, Copy, FolderOpen, Plus } from 'lucide-react'
import { useEffect, useState } from 'react'
import { revealFile } from '@/api/client'
import type { ProcessInfo } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Tooltip } from '@/components/ui/tooltip'
import { ProcessIcon } from '@/components/ProcessIcon'
import { dirOf, exeFromCmdline } from '@/lib/process'
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

/** Hijack source as a small dot; the tooltip names it. */
export function HijackDot({ source }: { source?: string | null }) {
  if (source !== 'manual' && source !== 'auto') return null
  const label = source === 'manual' ? '手动代理' : '自动代理（规则）'
  return (
    <Tooltip content={label}>
      <span aria-label={label} className={cn('size-1.5 shrink-0 rounded-full', source === 'manual' ? 'bg-success' : 'bg-info')} />
    </Tooltip>
  )
}

/**
 * 48px header row for the selected process: icon, name, sub-line
 * "PID · path args" (copy / reveal actions on hover), and 创建规则.
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
  const iconBtn = 'flex size-5 shrink-0 items-center justify-center rounded text-muted-foreground transition hover:bg-field hover:text-foreground'

  return (
    <div className="shrink-0">
      <div className="flex h-12 items-center gap-3">
        <ProcessIcon name={process.name} className="size-5.5" />
        <div className="group/path min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span className="truncate text-sm font-medium">{process.name}</span>
            <HijackDot source={process.hijack_source} />
          </div>
          <div className="flex min-w-0 items-center gap-1 text-2xs text-muted-foreground">
            <span className="tabular shrink-0">PID {process.pid}</span>
            {cmdline && (
              <>
                <span className="shrink-0 text-faint">·</span>
                <span className="selectable flex min-w-0 items-baseline" title={cmdline} data-testid="process-path">
                  {cwd && <span className="min-w-0 truncate">{cwd}</span>}
                  <span className="shrink-0 text-foreground-2">{exeName}</span>
                  {args && <span className="min-w-0 shrink-[100] truncate pl-1">{args}</span>}
                </span>
                {isLong && (
                  <button type="button" onClick={() => setExpanded(v => !v)} title={expanded ? '收起命令行' : '展开完整命令行'} aria-expanded={expanded} data-testid="process-cmdline-toggle" className={iconBtn}>
                    {expanded ? <ChevronUp className="size-3" /> : <ChevronDown className="size-3" />}
                  </button>
                )}
                <span className="flex shrink-0 items-center opacity-0 transition-opacity group-hover/path:opacity-100 focus-within:opacity-100">
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
      </div>
      {expanded && cmdline && (
        <p className="mb-2 break-all rounded-lg bg-surface-2 px-3 py-2 font-mono text-2xs text-muted-foreground">{cmdline}</p>
      )}
    </div>
  )
}
