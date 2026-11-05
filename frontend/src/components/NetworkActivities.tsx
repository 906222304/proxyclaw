import { useQuery } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { ArrowDown, ArrowUp, Moon } from 'lucide-react'
import { useMemo, useRef, useState } from 'react'
import { connectionsQuery } from '@/api/queries'
import type { NetworkConnection } from '@/api/types'
import { EmptyState } from '@/components/ui/misc'
import { SearchInput } from '@/components/ui/search-input'
import { Tooltip } from '@/components/ui/tooltip'
import {
  CONNECTION_STATES, PROXY_STATES, ROUTE_REASONS,
  columnsFor, filterRows, nextSort, remoteOf, rowId, sortRows, stateTone,
  type ColumnDef, type SortState,
} from '@/lib/connections'
import { cn } from '@/lib/utils'

const ROW_HEIGHT = 30

const stateDot: Record<ReturnType<typeof stateTone>, string> = {
  ok: 'bg-success shadow-[0_0_0_2.5px] shadow-success/18',
  bound: 'bg-violet shadow-[0_0_0_2.5px] shadow-violet/18',
  wait: 'bg-warning shadow-[0_0_0_2.5px] shadow-warning/18',
  idle: 'bg-faint',
}

export function NetworkActivities({ selectedPid }: { selectedPid: number | undefined }) {
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

  return (
    <div className="flex min-h-0 flex-1 flex-col px-5 pb-4">
      <div className="flex items-center gap-3 pb-3">
        <SearchInput
          value={filterText}
          onChange={setFilterText}
          placeholder="筛选目标地址或连接状态…"
          className="w-72"
        />
        {rows.length > 0 && (
          <span className="tabular ml-auto text-xs text-muted-foreground">
            {view.length === rows.length ? `${rows.length} 条连接` : `${view.length} / ${rows.length} 条连接`}
          </span>
        )}
      </div>

      {rows.length === 0 ? (
        <EmptyState
          icon={<Moon />}
          title={<>暂未检测到{selectedPid != null && ` ${processName} 的`}近期网络活动。</>}
          hint="进程开始访问网络后，连接将显示在此处。请确认代理引擎正在运行。"
        />
      ) : (
        <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl border border-border bg-card">
          <div ref={scrollRef} className="thin-scrollbar min-h-0 flex-1 overflow-auto" role="table" aria-rowcount={view.length}>
            <div
              role="row"
              className="sticky top-0 z-10 grid min-w-fit border-b border-border bg-surface-2 text-2xs text-muted-foreground"
              style={{ gridTemplateColumns: template }}
            >
              {columns.map(col => (
                <HeaderCell key={col.key} col={col} sort={sort} onSort={() => setSort(s => nextSort(s, col.key))} />
              ))}
            </div>
            {view.length === 0 ? (
              <div className="py-12 text-center text-xs text-muted-foreground">没有匹配的连接。</div>
            ) : (
              <div className="relative min-w-fit" style={{ height: virtualizer.getTotalSize() }}>
                {virtualizer.getVirtualItems().map(item => {
                  const c = view[item.index]!
                  return (
                    <div
                      key={item.key}
                      role="row"
                      className={cn(
                        'absolute inset-x-0 grid items-center border-b border-divider text-xs text-foreground transition-colors duration-100 hover:bg-muted/70',
                        // A socket whose owner exited: struck through and faded.
                        !c.pid_alive && 'line-through opacity-40',
                      )}
                      style={{ height: ROW_HEIGHT, transform: `translateY(${item.start}px)`, gridTemplateColumns: template }}
                    >
                      {columns.map(col => (
                        <div key={col.key} role="cell" className={cn('truncate px-3', col.mono && (col.key === 'remote' ? 'font-mono text-xs text-foreground-2' : 'tabular text-foreground-2'))}>
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

function HeaderCell({ col, sort, onSort }: { col: ColumnDef; sort: SortState | null; onSort: () => void }) {
  const active = sort?.key === col.key ? sort.dir : null
  return (
    <button
      type="button"
      role="columnheader"
      aria-sort={active === 'asc' ? 'ascending' : active === 'desc' ? 'descending' : 'none'}
      onClick={onSort}
      className={cn(
        'flex h-8 items-center gap-1 px-3 text-left font-medium tracking-[.02em] transition-colors hover:text-foreground',
        active && 'text-foreground',
      )}
    >
      {col.header}
      {active === 'asc' && <ArrowUp className="size-3" />}
      {active === 'desc' && <ArrowDown className="size-3" />}
    </button>
  )
}

function Cell({ conn, col }: { conn: NetworkConnection; col: ColumnDef }) {
  switch (col.key) {
    case 'process_name':
      return <span title={conn.process_name}>{conn.process_name}</span>
    case 'pid':
      return <>{conn.pid}</>
    case 'protocol':
      return (
        <span className={cn(
          'rounded-sm px-1.5 py-px text-2xs font-semibold tracking-[.04em]',
          conn.protocol === 'UDP' ? 'bg-violet-soft text-violet' : 'bg-info-soft text-info',
        )}>
          {conn.protocol}
        </span>
      )
    case 'remote': {
      const r = remoteOf(conn)
      return <span title={conn.dest && conn.dest !== r ? conn.dest : r}>{r}</span>
    }
    case 'state':
      return conn.state ? (
        <span className="inline-flex items-center gap-1.5">
          <span className={cn('size-1.5 shrink-0 rounded-full', stateDot[stateTone(conn.state)])} />
          {CONNECTION_STATES[conn.state] ?? conn.state}
        </span>
      ) : null
    case 'proxy_status': {
      const label = conn.proxy_status === 'PROXIED' || conn.proxy_status === 'IGNORED' ? PROXY_STATES[conn.proxy_status] : '直连'
      const tone = conn.proxy_status === 'PROXIED'
        ? 'bg-success-soft text-success'
        : conn.proxy_status === 'IGNORED'
          ? 'bg-warning-soft text-warning'
          : 'bg-muted text-muted-foreground'
      return (
        <Tooltip content={ROUTE_REASONS[conn.route_reason ?? '']}>
          <span className={cn('inline-flex h-[18px] items-center rounded-sm px-1.5 text-2xs font-medium', tone)}>{label}</span>
        </Tooltip>
      )
    }
    case 'local_port':
      return <>{conn.local_port}</>
  }
}
