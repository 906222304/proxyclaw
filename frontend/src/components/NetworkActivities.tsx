import { useQuery } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { ArrowDown, ArrowUp } from 'lucide-react'
import { useMemo, useRef, useState } from 'react'
import { connectionsQuery } from '@/api/queries'
import type { NetworkConnection, ProcessInfo } from '@/api/types'
import { ProcessContextHeader } from '@/components/ProcessContextHeader'
import { EmptyState } from '@/components/ui/misc'
import { SearchInput } from '@/components/ui/search-input'
import { Tooltip } from '@/components/ui/tooltip'
import {
  CONNECTION_STATES, PROXY_STATES, ROUTE_REASONS,
  columnsFor, filterRows, nextSort, remoteOf, rowId, sortRows, stateTone,
  type ColumnDef, type ColumnKey, type SortState,
} from '@/lib/connections'
import { cn } from '@/lib/utils'

const ROW_HEIGHT = 32

const stateDot: Record<ReturnType<typeof stateTone>, string> = {
  ok: 'bg-success',
  bound: 'bg-violet',
  wait: 'bg-warning',
  idle: 'bg-faint',
}

export function NetworkActivities({ selectedPid, process, onCreateRule }: {
  selectedPid: number | undefined
  process: ProcessInfo | null
  onCreateRule: () => void
}) {
  // Keyed by PID: switching selection shows an empty table until the new
  // PID's first response, never the previous PID's rows.
  const { data: rows = [] } = useQuery(connectionsQuery(selectedPid))
  const [filterText, setFilterText] = useState('')
  const [sort, setSort] = useState<SortState | null>(null)

  const columns = useMemo(() => columnsFor(selectedPid == null), [selectedPid])
  const view = useMemo(() => sortRows(filterRows(rows, filterText), sort), [rows, filterText, sort])
  const template = columns.map(c => c.width).join(' ')

  const scrollRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({
    count: view.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 16,
    getItemKey: i => rowId(view[i]!),
  })

  const processName = rows[0]?.process_name ?? '此进程'

  // Own toolbar row under the header, so the process path gets the full width.
  const tools = (
    <div className="flex h-10 shrink-0 items-center gap-3 pb-2">
      <SearchInput value={filterText} onChange={setFilterText} placeholder="筛选地址或状态…" className="w-56" />
      {rows.length > 0 && (
        <span className="tabular ml-auto text-2xs text-muted-foreground" data-testid="connection-count">
          {view.length === rows.length ? `${rows.length} 条连接` : `${view.length} / ${rows.length} 条连接`}
        </span>
      )}
    </div>
  )

  return (
    <div className="flex min-h-0 flex-1 flex-col pb-4">
      {process ? (
        <ProcessContextHeader process={process} onCreateRule={onCreateRule} />
      ) : (
        <div className="flex h-12 shrink-0 items-center gap-3">
          <div className="min-w-0 flex-1">
            <div className="text-sm font-medium">全部进程</div>
            <div className="text-2xs text-muted-foreground">所有进程的近期网络连接</div>
          </div>
        </div>
      )}
      {tools}

      {rows.length === 0 ? (
        <EmptyState
          title={<>暂未检测到{selectedPid != null && ` ${processName} 的`}近期网络活动</>}
          hint="进程开始访问网络后，连接将显示在此处。请确认代理引擎正在运行。"
        />
      ) : (
        <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl border border-border bg-card">
          <div ref={scrollRef} className="thin-scrollbar min-h-0 flex-1 overflow-auto" role="table" aria-rowcount={view.length}>
            <div
              role="row"
              className="sticky top-0 z-10 grid min-w-fit border-b border-divider bg-card text-2xs text-muted-foreground"
              style={{ gridTemplateColumns: template }}
            >
              {columns.map(col => (
                <HeaderCell key={col.key} col={col} sort={sort} onSort={key => setSort(s => nextSort(s, key))} />
              ))}
            </div>
            {view.length === 0 ? (
              <div className="py-12 text-center text-xs text-muted-foreground">没有匹配的连接</div>
            ) : (
              <div className="relative min-w-fit" style={{ height: virtualizer.getTotalSize() }}>
                {virtualizer.getVirtualItems().map(item => {
                  const c = view[item.index]!
                  return (
                    <div
                      key={item.key}
                      role="row"
                      className={cn(
                        'absolute inset-x-0 grid items-center border-b border-divider text-xs text-foreground transition-colors duration-100 hover:bg-surface-2',
                        // A socket whose owner exited: struck through and faded.
                        !c.pid_alive && 'line-through opacity-40',
                      )}
                      style={{ height: ROW_HEIGHT, transform: `translateY(${item.start}px)`, gridTemplateColumns: template }}
                    >
                      {columns.map(col => (
                        <div key={col.key} role="cell" className={cn('truncate px-2.5', col.mono && 'tabular text-foreground-2')}>
                          <Cell conn={c} col={col} />
                        </div>
                      ))}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function SortButton({ label, dir, onClick, className }: {
  label: string; dir: 'asc' | 'desc' | null; onClick: () => void; className?: string
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={`按${label}排序`}
      className={cn('flex h-full items-center gap-1 transition-colors hover:text-foreground', dir && 'text-foreground', className)}
    >
      {label}
      {dir === 'asc' && <ArrowUp className="size-3" />}
      {dir === 'desc' && <ArrowDown className="size-3" />}
    </button>
  )
}

/** Header cell; a folded column (PID, protocol) gets its own small sort target. */
function HeaderCell({ col, sort, onSort }: { col: ColumnDef; sort: SortState | null; onSort: (key: ColumnKey) => void }) {
  const dirOf = (key: ColumnKey) => (sort?.key === key ? sort.dir : null)
  const active = dirOf(col.key) ?? (col.sub ? dirOf(col.sub.key) : null)
  return (
    <div
      role="columnheader"
      aria-sort={active === 'asc' ? 'ascending' : active === 'desc' ? 'descending' : 'none'}
      className="flex h-8 items-center gap-1.5 px-2.5 text-left font-medium"
    >
      {col.sub && col.sub.before && <SortButton label={col.sub.header} dir={dirOf(col.sub.key)} onClick={() => onSort(col.sub!.key)} className="w-7 shrink-0 font-normal text-faint" />}
      <SortButton label={col.header} dir={dirOf(col.key)} onClick={() => onSort(col.key)} />
      {col.sub && !col.sub.before && <SortButton label={col.sub.header} dir={dirOf(col.sub.key)} onClick={() => onSort(col.sub!.key)} className="ml-0.5 font-normal text-faint" />}
    </div>
  )
}

function Cell({ conn, col }: { conn: NetworkConnection; col: ColumnDef }) {
  switch (col.key) {
    case 'process_name':
      return (
        <span title={`${conn.process_name} (PID ${conn.pid})`}>
          {conn.process_name}
          <span className="tabular ml-1.5 text-2xs text-faint">{conn.pid}</span>
        </span>
      )
    case 'pid':
      return <>{conn.pid}</>
    case 'protocol':
      return <span className="text-2xs text-faint">{conn.protocol}</span>
    case 'remote': {
      const r = remoteOf(conn)
      return (
        <span title={conn.dest && conn.dest !== r ? conn.dest : r}>
          <span className="mr-1.5 inline-block w-7 text-2xs text-faint">{conn.protocol}</span>
          {r}
        </span>
      )
    }
    case 'state':
      return conn.state ? (
        <span className="inline-flex items-center gap-1.5">
          <span className={cn('size-1.5 shrink-0 rounded-full', stateDot[stateTone(conn.state)])} />
          {CONNECTION_STATES[conn.state] ?? conn.state}
        </span>
      ) : null
    case 'proxy_status': {
      const proxied = conn.proxy_status === 'PROXIED'
      const ignored = conn.proxy_status === 'IGNORED'
      const label = proxied || ignored ? PROXY_STATES[conn.proxy_status] : '直连'
      return (
        <Tooltip content={ROUTE_REASONS[conn.route_reason ?? '']}>
          <span className={cn(proxied ? 'font-medium text-success' : ignored ? 'font-medium text-warning' : 'text-faint')}>{label}</span>
        </Tooltip>
      )
    }
    case 'local_port':
      return <>{conn.local_port}</>
  }
}
