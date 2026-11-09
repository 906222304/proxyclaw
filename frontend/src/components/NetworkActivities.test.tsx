// @vitest-environment jsdom
import { QueryClientProvider } from '@tanstack/react-query'
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createQueryClient } from '@/api/queries'
import type { ConnectionDecision, TcpConnection } from '@/api/types'
import { NetworkActivities } from '@/components/NetworkActivities'
import { TooltipProvider } from '@/components/ui/tooltip'

// v0.14 #4: the 代理 · 规则 cell of the network table, rendered from an
// /api/connections response (recorded, recomputed, stale, ignored, conflict).

function decision(p: Partial<ConnectionDecision>): ConnectionDecision {
  return { verdict: 'proxied', reason: 'none', rule_id: 'r-chrome', source: 'rule', group: 0, config_version: 7, at_ms: 1_700_000_000_000, pid: 10, psn: 1, ...p }
}

function row(port: number, p: Partial<TcpConnection>): TcpConnection {
  return {
    pid: 10, local_ip: '10.0.0.2', local_port: port, remote_ip: '1.1.1.1', remote_port: 443, state: 'ESTABLISHED',
    dest: '', hijacked: true, pid_alive: true, proxy_status: 'PROXIED', route_reason: 'none',
    decision_source: 'recorded', process_name: 'chrome.exe', ...p,
  }
}

const rule = (id: string, name: string) => ({
  id, name, enabled: true, process_name: 'chrome.exe', cmdline_pattern: '', hack_tree: true, protocol: 'both',
  proxy_group_id: 0, proxy: { type: 'socks5', host: '127.0.0.1', port: 7890 },
  dst_filter: { include_cidrs: [], exclude_cidrs: [], include_ports: [], exclude_ports: [] },
})

const routes: Record<string, unknown> = {
  '/api/auto-rules': [rule('r-chrome', 'Chrome 代理'), rule('r-dev', '开发工具')],
  '/api/connections': {
    active_pids: [10, 20, 30],
    config_version: 9,
    udp: [],
    tcp: [
      // Recorded, current, with a conflict.
      row(1001, { decision: decision({ config_version: 9 }), conflict: { manual: false, winner: 'r-chrome', shadowed_rule_ids: ['r-dev'] } }),
      // Recorded under older rules (stale), excluded by the rule's filter.
      row(1002, { proxy_status: 'IGNORED', route_reason: 'rule_exclude_port', decision: decision({ verdict: 'direct', reason: 'rule_exclude_port', group: null }) }),
      // Watchdog released it: the reason replaces the rule name.
      row(1003, { proxy_status: 'IGNORED', route_reason: 'watchdog', decision: decision({ verdict: 'direct', reason: 'watchdog', rule_id: null, source: null, group: null, pid: 0, config_version: 9 }) }),
      // No record: estimated from the current rules (manual hijack).
      row(1004, { pid: 20, process_name: 'ssh.exe', decision: null, decision_source: 'recomputed', estimate: { source: 'manual', rule_id: null } }),
      // Plain direct row of an unmatched process, after a config change: quiet.
      row(1005, { pid: 30, process_name: 'svchost.exe', hijacked: false, proxy_status: '-', route_reason: 'not-proxied',
        decision: decision({ verdict: 'direct', reason: 'not-proxied', rule_id: null, source: null, group: null }) }),
      // Rule deleted since: the id no longer resolves to a name.
      row(1006, { decision: decision({ rule_id: 'r-gone', source: 'tree', config_version: 9 }) }),
    ],
  },
}

let root: Root
let host: HTMLDivElement

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    const path = url.split('?')[0]!
    return new Response(JSON.stringify(routes[path] ?? {}), { status: 200 })
  }))
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue(
    { x: 0, y: 0, top: 0, left: 0, right: 800, bottom: 600, width: 800, height: 600, toJSON: () => ({}) } as DOMRect)
  vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockReturnValue(600)
  vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(800)
  host = document.createElement('div')
  document.body.appendChild(host)
})

afterEach(() => {
  act(() => root.unmount())
  host.remove()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

const flush = () => act(async () => { await new Promise(r => setTimeout(r, 20)) })

function cellOf(port: number): HTMLElement {
  const r = [...host.querySelectorAll<HTMLElement>('[role="row"]')].find(e => e.textContent?.includes(String(port)))
  expect(r, `row for local port ${port}`).toBeTruthy()
  return r!.querySelector<HTMLElement>('[data-testid="proxy-cell"]')!
}

describe('NetworkActivities 代理 · 规则', () => {
  it('shows the deciding rule, reasons and the conflict / stale markers', async () => {
    root = createRoot(host)
    act(() => root.render(
      <QueryClientProvider client={createQueryClient()}>
        <TooltipProvider>
          <NetworkActivities selectedPid={undefined} process={null} onCreateRule={() => {}} />
        </TooltipProvider>
      </QueryClientProvider>,
    ))
    await flush()
    await flush()

    // Header: the rule rides in the proxy column (5 columns, own sort target).
    const headers = [...host.querySelectorAll('[role="columnheader"]')].map(h => h.textContent)
    expect(headers).toHaveLength(5)
    expect(headers).toContain('代理规则')

    const current = cellOf(1001)
    expect(current.textContent).toBe('已代理Chrome 代理')
    expect(current.querySelector('[data-testid="hit-conflict"]')?.getAttribute('aria-label')).toBe('规则冲突')
    expect(current.querySelector('[data-testid="hit-stale"]')).toBeNull()

    const stale = cellOf(1002)
    expect(stale.textContent).toBe('已忽略Chrome 代理')
    expect(stale.querySelector('[data-testid="hit-stale"]')?.getAttribute('aria-label')).toBe('规则已变更')
    expect(stale.querySelector('[data-testid="hit-conflict"]')).toBeNull()

    expect(cellOf(1003).textContent).toBe('已忽略看门狗放行')

    const estimated = cellOf(1004)
    expect(estimated.textContent).toBe('已代理≈手动')
    expect(estimated.querySelector('[aria-label="估算"]')).not.toBeNull()

    const quiet = cellOf(1005)
    expect(quiet.textContent).toBe('直连')
    expect(quiet.querySelector('[data-testid="hit-rule"]')).toBeNull()
    expect(quiet.querySelector('[data-testid="hit-stale"]')).toBeNull()

    expect(cellOf(1006).textContent).toBe('已代理已删除的规则')
  })
})
