import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { ChevronDown, ChevronRight, Monitor, Zap, ZapOff } from 'lucide-react'
import { memo, useMemo, useRef, useState } from 'react'
import { hijackProcess, unhijackProcess } from '@/api/client'
import { activityQuery, isActive, useProcessTree } from '@/api/queries'
import { Badge, Segmented } from '@/components/ui/misc'
import { SearchInput } from '@/components/ui/search-input'
import { Tooltip } from '@/components/ui/tooltip'
import {
  countProcesses, filterTree, flattenTree, matchedPids, subtreeActive,
  type FlatRow, type ProcessFilter,
} from '@/lib/process'
import { pushError } from '@/lib/toast'
import { cn } from '@/lib/utils'

const ROW_HEIGHT = 28
const INDENT = 22
const LINE_X = 10

// Icons that failed to load once are not retried when a virtual row remounts.
const failedIcons = new Set<string>()

const FILTERS: { value: ProcessFilter; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'proxied', label: '代理' },
  { value: 'direct', label: '直连' },
]

export function ProcessTree({ selectedPid, onSelect }: {
  selectedPid: number | undefined
  onSelect: (pid: number | undefined) => void
}) {
  const queryClient = useQueryClient()
  const processes = useProcessTree()
  const { data: activity } = useQuery(activityQuery(queryClient))

  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<ProcessFilter>('all')
  // Explicit expand/collapse per pid. Absent = default: expanded while
  // searching, collapsed otherwise. A click always writes here, so collapse
  // works during search too.
  const [expandedPids, setExpandedPids] = useState<ReadonlyMap<number, boolean>>(new Map())

  const searching = query.trim() !== ''
  const now = Date.now()
  const activeSelf = (pid: number) => isActive(activity, pid, now)

  const total = useMemo(() => countProcesses(processes), [processes])
  const visible = useMemo(() => filterTree(processes, query, filter), [processes, query, filter])
  const matched = useMemo(() => matchedPids(processes, query, filter), [processes, query, filter])
  const activeSubtree = useMemo(() => subtreeActive(processes, activeSelf), [processes, activity])
  const isExpanded = (pid: number) => expandedPids.get(pid) ?? searching
  const rows = useMemo(
    () => flattenTree(visible, isExpanded),
      [visible, expandedPids, searching],
  )

  const toggle = (pid: number) => {
    setExpandedPids(prev => new Map(prev).set(pid, !(prev.get(pid) ?? searching)))
  }

  // v0.9.0+: Hack and Unhack are always tree-mode. The backend pushes a
  // fresh snapshot after the change, which lands in the query cache.
  const hack = useMutation({
    mutationFn: (pid: number) => hijackProcess(pid),
    onError: e => pushError(e, '启用代理失败'),
  })
  const unhack = useMutation({
    mutationFn: (pid: number) => unhijackProcess(pid, true),
    onError: e => pushError(e, '取消代理失败'),
  })

  const scrollRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
    getItemKey: i => rows[i]!.node.pid,
  })
  const items = virtualizer.getVirtualItems()

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="space-y-2 px-3 pt-3 pb-2">
        <SearchInput value={query} onChange={setQuery} placeholder="搜索 PID 或进程名称…" />
        <Segmented value={filter} onChange={setFilter} options={FILTERS} className="flex w-full" />
      </div>

      <button
        type="button"
        onClick={() => onSelect(undefined)}
        className={cn(
          'mx-2 mb-1 flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-sm transition-colors',
          selectedPid == null ? 'bg-selected font-medium text-primary' : 'text-muted-foreground hover:bg-muted',
        )}
      >
        <Monitor className="size-4" />
        全部进程
        <span className="ml-auto font-mono text-[11px] text-muted-foreground">{total}</span>
      </button>

      <div ref={scrollRef} className="thin-scrollbar min-h-0 flex-1 select-none overflow-auto px-2 pb-3">
        {rows.length === 0 ? (
          <div className="px-3 py-4 text-center text-xs text-muted-foreground">没有找到进程。</div>
        ) : (
          <div className="relative w-max min-w-full" style={{ height: virtualizer.getTotalSize() }}>
            <div style={{ transform: `translateY(${items[0]?.start ?? 0}px)` }}>
              {items.map(item => {
                const row = rows[item.index]!
                return (
                  <TreeRow
                    key={item.key}
                    row={row}
                    selected={selectedPid === row.node.pid}
                    active={activeSelf(row.node.pid)}
                    activeSubtree={activeSubtree}
                    matched={matched.has(row.node.pid)}
                    onSelect={onSelect}
                    onToggle={toggle}
                    onHack={hack.mutate}
                    onUnhack={unhack.mutate}
                  />
                )
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

const lineClass = (on: boolean) => (on ? 'bg-muted-foreground/60' : 'bg-border')

const TreeRow = memo(function TreeRow({ row, selected, active, activeSubtree, matched, onSelect, onToggle, onHack, onUnhack }: {
  row: FlatRow
  selected: boolean
  active: boolean
  activeSubtree: Set<number>
  matched: boolean
  onSelect: (pid: number) => void
  onToggle: (pid: number) => void
  onHack: (pid: number) => void
  onUnhack: (pid: number) => void
}) {
  const { node, depth, hasChildren, expanded, rails, nextSibling } = row
  const manual = node.hijack_source === 'manual'
  const auto = node.hijack_source === 'auto'
  const showHack = !node.hijacked && !auto
  const subtreeOn = activeSubtree.has(node.pid)
  // Text dims on self-idle; the icon dims only when the whole subtree is idle.
  const textDim = !selected && !active ? 'opacity-50' : ''
  const iconDim = !selected && !subtreeOn ? 'opacity-50' : ''
  const [iconFailed, setIconFailed] = useState(() => failedIcons.has(node.name))

  return (
    <div
      className={cn(
        'group relative flex cursor-pointer items-center rounded-md pr-2 transition-colors',
        selected
          ? active ? 'bg-selected' : 'bg-muted'
          : matched ? 'bg-amber-400/15' : 'hover:bg-muted',
      )}
      style={{ height: ROW_HEIGHT, paddingLeft: depth * INDENT }}
      title={node.cmdline || node.name}
      onClick={() => onSelect(node.pid)}
    >
      {/* Guide lines: ancestor rails, then this row's elbow. */}
      {rails.map((rail, k) => rail != null && (
        <span
          key={k}
          className={cn('absolute top-0 h-full w-px', lineClass(activeSubtree.has(rail)))}
          style={{ left: k * INDENT + LINE_X }}
        />
      ))}
      {depth > 0 && (
        <>
          <span className={cn('absolute top-0 h-1/2 w-px', lineClass(subtreeOn))} style={{ left: (depth - 1) * INDENT + LINE_X }} />
          <span className={cn('absolute top-1/2 h-px', lineClass(subtreeOn))} style={{ left: (depth - 1) * INDENT + LINE_X, width: INDENT - LINE_X }} />
          {nextSibling != null && (
            <span className={cn('absolute top-1/2 h-1/2 w-px', lineClass(activeSubtree.has(nextSibling)))} style={{ left: (depth - 1) * INDENT + LINE_X }} />
          )}
        </>
      )}

      <span
        className="flex w-5 shrink-0 items-center justify-center"
        onClick={e => { e.stopPropagation(); if (hasChildren) onToggle(node.pid) }}
      >
        {hasChildren && (
          <span className={cn('rounded p-0.5 hover:bg-border', subtreeOn ? 'text-foreground/80' : 'text-muted-foreground')}>
            {expanded ? <ChevronDown className="size-3" /> : <ChevronRight className="size-3" />}
          </span>
        )}
      </span>

      <span className="flex flex-1 items-center gap-2">
        {iconFailed ? (
          <Monitor className={cn('size-4 shrink-0 text-muted-foreground', iconDim)} />
        ) : (
          <img
            src={`/api/icon?name=${encodeURIComponent(node.name)}`}
            alt=""
            loading="lazy"
            className={cn('size-4 shrink-0', iconDim)}
            onError={() => { failedIcons.add(node.name); setIconFailed(true) }}
          />
        )}
        {node.hijacked && (
          <span className="size-1.5 shrink-0 rounded-full bg-emerald-500" title={manual ? '手动代理' : '自动代理'} />
        )}
        <span className={cn(
          'whitespace-nowrap font-mono tracking-tight',
          depth === 0 ? 'text-[13px]' : 'text-xs',
          selected ? 'font-semibold text-primary' : 'text-foreground',
          textDim,
        )}>
          {node.name}
        </span>
        {manual && <Badge tone="green" className="h-4 px-1 text-[10px]">手动</Badge>}
        {auto && <Badge tone="blue" className="h-4 px-1 text-[10px]">自动</Badge>}
        <span className="ml-auto flex shrink-0 items-center gap-1 pl-2">
          {showHack && (
            <Tooltip content="启用代理">
              <button
                type="button"
                aria-label="启用代理"
                onClick={e => { e.stopPropagation(); onHack(node.pid) }}
                className="flex size-6 items-center justify-center rounded text-muted-foreground opacity-0 transition hover:bg-border hover:text-amber-500 group-hover:opacity-100 focus-visible:opacity-100"
              >
                <Zap className="size-3.5" />
              </button>
            </Tooltip>
          )}
          {manual && (
            <Tooltip content="取消代理">
              <button
                type="button"
                aria-label="取消代理"
                onClick={e => { e.stopPropagation(); onUnhack(node.pid) }}
                className="flex size-6 items-center justify-center rounded text-emerald-500 transition hover:bg-border hover:text-red-500"
              >
                <ZapOff className="size-3.5" />
              </button>
            </Tooltip>
          )}
          <span className={cn('font-mono text-[11px]', selected ? 'text-primary' : 'text-muted-foreground', textDim)}>
            {node.pid}
          </span>
        </span>
      </span>
    </div>
  )
})
