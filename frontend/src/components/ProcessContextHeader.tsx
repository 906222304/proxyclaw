import { Check, ChevronDown, ChevronUp, Copy, FolderOpen, Plus } from 'lucide-react'
import { useEffect, useState } from 'react'
import { revealFile } from '@/api/client'
import type { ProcessInfo } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/misc'
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

export function ProcessContextHeader({ process, onCreateRule }: {
  process: ProcessInfo | null
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

  if (!process) return null
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

  return (
    <div className="mx-5 mb-3 rounded-xl border border-border bg-card px-4 py-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex min-w-0 items-center gap-2">
          <img
            src={`/api/icon?name=${encodeURIComponent(process.name)}`}
            alt=""
            className="size-5 shrink-0"
            onError={e => { e.currentTarget.style.visibility = 'hidden' }}
          />
          <span className="truncate font-mono text-sm font-semibold">{process.name}</span>
          {process.hijack_source === 'manual' && <Badge tone="green">手动</Badge>}
          {process.hijack_source === 'auto' && <Badge tone="blue">自动</Badge>}
          <span className="font-mono text-xs text-muted-foreground">PID {process.pid}</span>
        </div>
        <Button size="sm" variant="ghost" onClick={onCreateRule} title="为此进程创建规则">
          <Plus /> 创建规则
        </Button>
      </div>

      {cmdline && (
        <div className="group/path mt-2 flex flex-wrap items-center gap-1 text-xs">
          <button
            type="button"
            onClick={locate}
            title="打开程序所在文件夹"
            className={cn(
              'shrink-0 rounded p-1 transition-colors',
              located ? 'bg-emerald-500/10 text-emerald-600' : 'text-muted-foreground hover:bg-muted hover:text-foreground',
            )}
          >
            <FolderOpen className="size-3.5" />
          </button>
          <span className="inline-flex shrink-0 items-center font-mono text-[11px]">
            {cwd && <span className="max-w-[220px] truncate rounded-l bg-muted px-1.5 py-0.5 text-muted-foreground" title={cwd}>{cwd}</span>}
            <span className={cn('bg-muted px-1.5 py-0.5 font-semibold', cwd ? 'rounded-r border-l border-border' : 'rounded')}>{exeName}</span>
          </span>
          {args && (
            <span className={cn('ml-1 font-mono text-[11px] text-muted-foreground', !expanded && isLong ? 'max-w-[12rem] truncate' : 'break-all')}>
              {args}
            </span>
          )}
          {isLong && (
            <button type="button" onClick={() => setExpanded(v => !v)} title={expanded ? '收起' : '展开'}
              className="shrink-0 rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground">
              {expanded ? <ChevronUp className="size-3.5" /> : <ChevronDown className="size-3.5" />}
            </button>
          )}
          {cwd && (
            <button type="button" onClick={() => copy(cwd, 'cwd')} title="复制工作目录"
              className="shrink-0 rounded p-1 text-muted-foreground opacity-0 transition-opacity hover:bg-muted hover:text-foreground group-hover/path:opacity-100">
              {copied === 'cwd' ? <Check className="size-3.5 text-emerald-500" /> : <Copy className="size-3.5" />}
            </button>
          )}
          <button type="button" onClick={() => copy(cmdline, 'full')} title="复制完整命令行"
            className="flex shrink-0 items-center gap-0.5 rounded px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground opacity-0 transition-opacity hover:bg-muted hover:text-foreground group-hover/path:opacity-100">
            {copied === 'full' ? <Check className="size-3 text-emerald-500" /> : <><Copy className="size-3" /><span>全部</span></>}
          </button>
        </div>
      )}
    </div>
  )
}
