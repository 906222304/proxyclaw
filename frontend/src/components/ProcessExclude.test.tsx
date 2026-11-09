// @vitest-environment jsdom
import { QueryClientProvider } from '@tanstack/react-query'
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useExcludeProcess, useRestoreProcess } from '@/api/mutations'
import { createQueryClient } from '@/api/queries'
import { queryKeys } from '@/api/queryKeys'
import type { AutoRule, ProcessInfo } from '@/api/types'
import { ProcessContextHeader, excludeMenuItems } from '@/components/ProcessContextHeader'
import { TooltipProvider } from '@/components/ui/tooltip'
import { matchedProcessList } from '@/components/RuleEditorDialog'

const rule = (id: string, matched: { pid: number; name?: string; excluded?: boolean }[]): AutoRule => ({
  id, name: id, enabled: true, process_name: 'app.exe', cmdline_pattern: '', hack_tree: true,
  dst_filter: { include_cidrs: [], exclude_cidrs: [], include_ports: [], exclude_ports: [] },
  proxy_group_id: 0, proxy: { type: 'socks5', host: '127.0.0.1', port: 7890 },
  matched_pids: matched.map(m => ({ pid: m.pid, name: m.name ?? 'app.exe', excluded: !!m.excluded })),
})

let root: Root
let host: HTMLDivElement
let fetchMock: ReturnType<typeof vi.fn>
let rulesResponse: AutoRule[] = []

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock = vi.fn(async (url: string) => {
    const path = url.split('?')[0]!
    if (path === '/api/auto-rules') return new Response(JSON.stringify(rulesResponse), { status: 200 })
    return new Response(JSON.stringify({ success: true }), { status: 200 })
  })
  vi.stubGlobal('fetch', fetchMock)
  host = document.createElement('div')
  document.body.appendChild(host)
  root = createRoot(host)
})

afterEach(() => {
  act(() => root.unmount())
  host.remove()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

const flush = () => act(async () => { await new Promise(r => setTimeout(r, 20)) })
const calls = () => fetchMock.mock.calls.map(([url, init]) => `${(init as RequestInit | undefined)?.method ?? 'GET'} ${url}`)

function renderHeader(process: ProcessInfo, rules: AutoRule[]) {
  rulesResponse = rules
  const qc = createQueryClient()
  qc.setQueryData(queryKeys.autoRules, rules)
  act(() => root.render(<QueryClientProvider client={qc}><TooltipProvider><ProcessContextHeader process={process} onCreateRule={() => {}} /></TooltipProvider></QueryClientProvider>))
  return qc
}

describe('selected-process header', () => {
  it('shows the ⋯ menu for an auto-proxied process, no badge', async () => {
    renderHeader({ pid: 10, parent_pid: 1, name: 'app.exe', hijacked: true, hijack_source: 'auto:a' }, [rule('a', [{ pid: 10 }])])
    await flush()
    expect(host.querySelector('[aria-label="进程操作"]')).not.toBeNull()
    expect(host.querySelector('[data-testid="excluded-badge"]')).toBeNull()
  })
  it('shows 已排除 and the menu for an excluded process', async () => {
    renderHeader({ pid: 10, parent_pid: 1, name: 'app.exe', hijacked: false, hijack_source: '' }, [rule('a', [{ pid: 10, excluded: true }])])
    await flush()
    expect(host.querySelector('[data-testid="excluded-badge"]')?.textContent).toBe('已排除')
    expect(host.querySelector('[aria-label="进程操作"]')).not.toBeNull()
  })
  it('has no menu for a manual hijack or a direct process', async () => {
    renderHeader({ pid: 10, parent_pid: 1, name: 'app.exe', hijacked: true, hijack_source: 'manual' }, [rule('a', [{ pid: 10 }])])
    await flush()
    expect(host.querySelector('[aria-label="进程操作"]')).toBeNull()
    renderHeader({ pid: 20, parent_pid: 1, name: 'x.exe', hijacked: false, hijack_source: '' }, [rule('a', [{ pid: 10 }])])
    await flush()
    expect(host.querySelector('[aria-label="进程操作"]')).toBeNull()
  })
})

describe('menu items', () => {
  it('labels exclude with the restart caveat and restore plainly', () => {
    const run = vi.fn()
    const ex = excludeMenuItems({ kind: 'exclude', ruleIds: ['a'] }, run)
    expect(ex).toHaveLength(1)
    expect(ex[0]!.label).toBe('此进程不走代理')
    expect(ex[0]!.hint).toBe('进程重启后恢复')
    ex[0]!.onSelect()
    expect(run).toHaveBeenCalledWith({ kind: 'exclude', ruleIds: ['a'] })
    expect(excludeMenuItems({ kind: 'restore', ruleIds: ['a'] }, run)[0]!.label).toBe('恢复代理')
    expect(excludeMenuItems(null, run)).toEqual([])
    expect(excludeMenuItems({ kind: 'exclude', ruleIds: ['a'] }, run, true)[0]!.disabled).toBe(true)
  })
})

describe('exclude / restore mutations', () => {
  function Harness({ onReady }: { onReady: (m: { ex: ReturnType<typeof useExcludeProcess>; re: ReturnType<typeof useRestoreProcess> }) => void }) {
    onReady({ ex: useExcludeProcess(), re: useRestoreProcess() })
    return null
  }

  it('excludes from every rule, restores, and refetches the rule list', async () => {
    const qc = createQueryClient()
    qc.setQueryData(queryKeys.autoRules, [])
    let m!: { ex: ReturnType<typeof useExcludeProcess>; re: ReturnType<typeof useRestoreProcess> }
    // An observer keeps the rules query active so invalidation refetches it.
    const { autoRulesQuery } = await import('@/api/queries')
    const { useQuery } = await import('@tanstack/react-query')
    function Observer() { useQuery(autoRulesQuery); return null }
    act(() => root.render(<QueryClientProvider client={qc}><Observer /><Harness onReady={x => { m = x }} /></QueryClientProvider>))
    await flush()
    fetchMock.mockClear()

    await act(async () => { await m.ex.mutateAsync({ pid: 10, ruleIds: ['a', 'b'] }) })
    await flush()
    expect(calls()).toEqual(expect.arrayContaining(['POST /api/auto-rules/a/exclude/10', 'POST /api/auto-rules/b/exclude/10', 'GET /api/auto-rules']))

    fetchMock.mockClear()
    await act(async () => { await m.re.mutateAsync({ pid: 10, ruleIds: ['a'] }) })
    await flush()
    expect(calls()).toEqual(expect.arrayContaining(['DELETE /api/auto-rules/a/exclude/10', 'GET /api/auto-rules']))
    expect(calls()).not.toContain('DELETE /api/auto-rules/b/exclude/10')
  })
})

describe('rule editor matched list', () => {
  it('sorts proxied first and excluded last', () => {
    const r = rule('a', [{ pid: 30, name: 'b.exe', excluded: true }, { pid: 20, name: 'b.exe' }, { pid: 10, name: 'a.exe' }])
    expect(matchedProcessList(r).map(p => p.pid)).toEqual([10, 20, 30])
    expect(matchedProcessList(undefined)).toEqual([])
  })
})
