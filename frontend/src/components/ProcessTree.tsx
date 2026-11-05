import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { ChevronDown, ChevronRight, Monitor, Zap, ZapOff } from 'lucide-react'
import { memo, useMemo, useRef, useState } from 'react'
import { hijackProcess, unhijackProcess } from '@/api/client'
import { activityQuery, isActive, useProcessTree } from '@/api/queries'
import { ProcessIcon } from '@/components/ProcessIcon'
import { Segmented } from '@/components/ui/misc'
import { HijackDot } from '@/components/ProcessContextHeader'
import { SearchInput } from '@/components/ui/search-input'
import { Tooltip } from '@/components/ui/tooltip'
import {
  countProcesses, filterTree, flattenTree, matchedPids, rowIndent, subtreeActive,
  type FlatRow, type ProcessFilter,
} from '@/lib/process'
import { pushError } from '@/lib/toast'
import { cn } from '@/lib/utils'

const ROW_HEIGHT = 30
// One indent step; the cap (MAX_INDENT_DEPTH) bounds the total to 55 px so
// deep names still fit the 240 px sidebar.
const INDENT = 11
// Guide-line x offset inside a step: centre of the 14 px chevron gutter.
const LINE_X = 7

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
      <div className="space-y-1.5 px-3 pt-1 pb-2">
        <SearchInput value={query} onChange={setQuery} placeholder="搜索 PID 或进程名称…" />
        <Segmented value={filter} onChange={setFilter} options={FILTERS} size="sm" className="flex w-full" />
      </div>

      <button
        type="button"
        onClick={() => onSelect(undefined)}
        className={cn(
          'mx-2 mb-1 flex h-7.5 items-center gap-2 rounded-md px-2.5 text-xs transition-colors duration-150',
          selectedPid == null ? 'bg-selected font-medium text-foreground [&>svg]:text-primary' : 'text-foreground-2 hover:bg-field',
        )}
      >
        <Monitor className="size-3.5" />
        全部进程
        <span data-testid="process-count" className="tabular ml-auto text-2xs text-muted-foreground">{total}</span>
      </button>

      <div ref={scrollRef} className="thin-scrollbar min-h-0 flex-1 select-none overflow-y-auto overflow-x-hidden px-2 pb-3">
        {rows.length === 0 ? (
          <div className="px-3 py-8 text-center text-2xs text-muted-foreground">没有找到进程</div>
        ) : (
          <div className="relative w-full" style={{ height: virtualizer.getTotalSize() }}>
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

// Guide lines are drawn only for subtrees with network activity; idle
// branches stay unlined so the tree reads as a plain list.
const lineClass = (on: boolean) => (on ? 'bg-muted-foreground/45' : 'bg-transparent')
const dashClass = (on: boolean) => (on ? 'border-muted-foreground/50' : 'border-transparent')

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
  const { node, depth, hasChildren, expanded, nextSibling } = row
  const { level, compressed, rails } = rowIndent(row)
  const elbowX = (level - 1) * INDENT + LINE_X
  const manual = node.hijack_source === 'manual'
  const auto = node.hijack_source === 'auto'
  const idle = !selected && !active
  const showHack = !node.hijacked && !auto
  const subtreeOn = activeSubtree.has(node.pid)
  // Idle text is muted (not faded); the icon greys only when the whole
  // subtree is idle.
  const iconDim = !selected && !subtreeOn ? 'grayscale' : ''

  return (
    <div
      className={cn(
        'group relative flex items-center rounded-md pr-2 transition-colors duration-100',
        selected
          ? active ? 'bg-selected' : 'bg-hover'
          : 'hover:bg-field',
      )}
      style={{ height: ROW_HEIGHT, paddingLeft: level * INDENT }}
      title={(node.cmdline || node.name) + (compressed ? `\n（第 ${depth} 层）` : '')}
      data-depth={depth}
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
      {level > 0 && !compressed && (
        <>
          <span className={cn('absolute top-0 h-1/2 w-px', lineClass(subtreeOn))} style={{ left: elbowX }} />
          <span className={cn('absolute top-1/2 h-px', lineClass(subtreeOn))} style={{ left: elbowX, width: INDENT - LINE_X }} />
          {nextSibling != null && (
            <span className={cn('absolute top-1/2 h-1/2 w-px', lineClass(activeSubtree.has(nextSibling)))} style={{ left: elbowX }} />
          )}
        </>
      )}
      {/* Deeper than the cap: levels are folded into the last step, drawn as
          a dashed rail with a short elbow (full depth is in the tooltip). */}
      {compressed && (
        <>
          <span
            data-testid="compressed-guide"
            className={cn('absolute top-0 h-full w-0 border-l border-dashed', dashClass(subtreeOn))}
            style={{ left: elbowX }}
          />
          <span className={cn('absolute top-1/2 h-px', lineClass(subtreeOn))} style={{ left: elbowX, width: INDENT - LINE_X }} />
        </>
      )}

      <span
        className="flex w-3.5 shrink-0 items-center justify-center"
        onClick={e => { e.stopPropagation(); if (hasChildren) onToggle(node.pid) }}
      >
        {hasChildren && (
          <span className={cn('rounded-sm p-0.5 hover:bg-field-hover', subtreeOn ? 'text-foreground-2' : 'text-faint')}>
            {expanded ? <ChevronDown className="size-3" /> : <ChevronRight className="size-3" />}
          </span>
        )}
      </span>

      <span className="flex min-w-0 flex-1 items-center gap-1.5">
        <ProcessIcon name={node.name} className={cn('size-4', iconDim)} />
        <span className={cn(
          'min-w-0 truncate text-xs',
          selected ? 'font-medium text-foreground' : idle ? 'text-muted-foreground' : 'text-foreground',
          matched && 'font-semibold text-foreground',
        )} title={node.name}>
          {node.name}
        </span>
        {node.hijacked && (manual || auto
          ? <HijackDot source={node.hijack_source} />
          : <span className="size-1.5 shrink-0 rounded-full bg-success" title="已代理" />)}
        {/* The hover-only hack button sits on top of the PID (which fades out)
            instead of taking width, so hovering never squeezes the name. */}
        <span className="relative ml-auto flex shrink-0 items-center pl-1.5">
          {showHack && (
            <Tooltip content="启用代理">
              <button
                type="button"
                aria-label="启用代理"
                onClick={e => { e.stopPropagation(); onHack(node.pid) }}
                className="peer absolute top-1/2 right-0 flex size-6 -translate-y-1/2 items-center justify-center rounded text-muted-foreground opacity-0 transition hover:bg-field-hover hover:text-warning group-hover:opacity-100 focus-visible:opacity-100"
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
                className="peer absolute top-1/2 right-0 flex size-6 -translate-y-1/2 items-center justify-center rounded text-success opacity-0 transition hover:bg-field-hover hover:text-destructive group-hover:opacity-100 focus-visible:opacity-100"
              >
                <ZapOff className="size-3.5" />
              </button>
            </Tooltip>
          )}
          <span className={cn(
            'tabular text-2xs transition',
            selected ? 'text-primary' : 'text-faint',
            (showHack || manual) && 'group-hover:opacity-0 peer-focus-visible:opacity-0',
          )}>
            {node.pid}
          </span>
        </span>
      </span>
    </div>
  )
})
