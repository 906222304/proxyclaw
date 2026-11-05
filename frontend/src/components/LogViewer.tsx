import { useQuery } from '@tanstack/react-query'
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { revealFile } from '@/api/client'
import { logQuery } from '@/api/queries'
import { Button } from '@/components/ui/button'
import { Dialog } from '@/components/ui/dialog'
import { SearchInput } from '@/components/ui/search-input'
import { Select } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'

const PROBLEM_LINE = /^\S+\s+\S+\s+\[(W|E|C|WARN|WARNING|ERROR|CRITICAL)\]/

export function filterLog(text: string, query: string, level: 'all' | 'problems'): string {
  const needle = query.trim().toLocaleLowerCase()
  return text.split('\n').filter(line => {
    if (needle && !line.toLocaleLowerCase().includes(needle)) return false
    return level === 'all' || PROBLEM_LINE.test(line)
  }).join('\n')
}

export function LogViewer() {
  const [open, setOpen] = useState(false)
  const [automatic, setAutomatic] = useState(true)
  const [query, setQuery] = useState('')
  const [level, setLevel] = useState<'all' | 'problems'>('all')
  const [actionMessage, setActionMessage] = useState('')
  const pane = useRef<HTMLPreElement>(null)
  const follow = useRef(true)

  const log = useQuery(logQuery(open, automatic))
  const snapshot = log.data
  const filtered = useMemo(() => filterLog(snapshot?.text ?? '', query, level), [snapshot, query, level])
  const updatedAt = log.dataUpdatedAt ? new Date(log.dataUpdatedAt).toLocaleTimeString('zh-CN') : ''

  useEffect(() => { setActionMessage('') }, [open, automatic])

  // Keep the view pinned to the newest lines unless the user scrolled up.
  useLayoutEffect(() => {
    const el = pane.current
    if (el && follow.current) el.scrollTop = el.scrollHeight
  }, [filtered])

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(filtered)
      setActionMessage('已复制当前显示的日志')
    } catch {
      setActionMessage('复制失败，请选中日志后按 Ctrl+C。')
    }
  }
  const reveal = async () => {
    if (!snapshot) return
    try {
      await revealFile(snapshot.path)
      setActionMessage('')
    } catch {
      setActionMessage('打开文件位置失败，请稍后重试。')
    }
  }

  const placeholder = log.isFetching && !snapshot
    ? '正在读取日志…'
    : snapshot && !snapshot.exists ? '日志文件尚未生成。'
      : snapshot?.text ? '没有匹配的日志。' : '暂无日志记录。'

  return (
    <>
      <Button size="sm" onClick={() => setOpen(true)}>查看日志</Button>
      <Dialog
        open={open}
        onOpenChange={setOpen}
        title="运行日志"
        description="查看最近的连接与错误记录，自动刷新间隔为 3 秒。"
        className="h-[80vh] max-w-5xl"
      >
        <div className="flex h-full min-h-0 flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <SearchInput value={query} onChange={setQuery} placeholder="搜索日志…" className="min-w-32 flex-1" />
            <Select
              value={level}
              onValueChange={v => setLevel(v as 'all' | 'problems')}
              ariaLabel="日志筛选"
              className="h-8 w-36 text-xs"
              options={[{ value: 'all', label: '全部日志' }, { value: 'problems', label: '警告和错误' }]}
            />
            <label className="flex items-center gap-2 whitespace-nowrap text-xs">
              <Switch checked={automatic} onCheckedChange={setAutomatic} aria-label="自动刷新" />自动刷新
            </label>
            <Button size="sm" disabled={log.isFetching} onClick={() => void log.refetch()}>刷新</Button>
            <Button size="sm" disabled={!filtered} onClick={copy}>复制日志</Button>
          </div>
          {log.error && (
            <p role="alert" className="text-xs text-destructive">
              {log.error instanceof Error ? log.error.message : '日志读取失败，请稍后重试。'}
            </p>
          )}
          <pre
            ref={pane}
            tabIndex={0}
            aria-label="日志内容"
            onScroll={e => {
              const el = e.currentTarget
              follow.current = el.scrollHeight - el.scrollTop - el.clientHeight < 32
            }}
            className="thin-scrollbar min-h-[200px] flex-1 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-divider bg-surface-2 p-3 font-mono text-[11.5px] leading-5"
          >
            {filtered || placeholder}
          </pre>
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
            <span>
              {snapshot?.truncated ? '显示最新片段，完整记录请打开文件位置查看。' : '最多显示最近 1000 行。'}
              {updatedAt && ` 更新于 ${updatedAt}`}
            </span>
            <Button size="sm" disabled={!snapshot} onClick={reveal}>打开文件位置</Button>
          </div>
          {snapshot && <p className="break-all text-xs text-muted-foreground">{snapshot.path}</p>}
          {actionMessage && <p role="status" className="text-xs">{actionMessage}</p>}
        </div>
      </Dialog>
    </>
  )
}
