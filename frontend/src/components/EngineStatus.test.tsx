// @vitest-environment jsdom
import { QueryClientProvider } from '@tanstack/react-query'
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createQueryClient } from '@/api/queries'
import { ConfigEditor } from '@/components/ConfigEditor'
import { TooltipProvider } from '@/components/ui/tooltip'

let routes: Record<string, unknown>
let putCalls: { url: string; body: unknown }[]
let root: Root
let host: HTMLDivElement

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  putCalls = []
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  vi.stubGlobal('matchMedia', (q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }))
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const path = url.split('?')[0]!
    if (init?.method === 'PUT') {
      putCalls.push({ url: path, body: init.body ? JSON.parse(String(init.body)) : null })
      return new Response('', { status: 200 })
    }
    return new Response(JSON.stringify(routes[path] ?? {}), { status: 200 })
  }))
  host = document.createElement('div')
  document.body.appendChild(host)
})

afterEach(() => {
  act(() => root.unmount())
  host.remove()
  vi.unstubAllGlobals()
})

const flush = () => act(async () => { await new Promise(r => setTimeout(r, 20)) })

async function render() {
  root = createRoot(host)
  act(() => root.render(
    <QueryClientProvider client={createQueryClient()}>
      <TooltipProvider><ConfigEditor /></TooltipProvider>
    </QueryClientProvider>,
  ))
  await flush()
}

describe('EngineStatusCard and config import', () => {
  const baseConfig = { version: 2, ui: { close_to_tray: true }, log_level: 'info', dns: { enabled: false } }

  it('shows WinDivert driver failure, per-layer badges, DNS recovery failure, and decision counts', async () => {
    routes = {
      '/api/config': baseConfig,
      '/api/autostart': { enabled: false, start_minimized: false, location_trusted: true },
      '/api/stats': {
        hijacked_pids: 0,
        auto_rules_count: 2,
        tree_ready: true,
        process_count: 142,
        dns: { state: 'off', recovery: 'failed' },
        interception: {
          mode: 'windivert',
          active: false,
          error: 'windivert_driver_failed',
          layers: {
            tcp_socket: false,
            tcp_network: false,
            tcp_v6: false,
            udp_socket: false,
            udp_network: false,
          },
        },
        decisions: { written: 128, dropped: 3, capacity: 4096 },
      },
    }
    await render()

    const card = host.querySelector('[data-testid="engine-status-card"]')!
    expect(card.textContent).toContain('启动失败')
    expect(card.textContent).toContain('142 个运行中进程')

    const err = host.querySelector('[data-testid="engine-interception-error"]')
    expect(err?.textContent).toContain('WinDivert 驱动加载失败')
    expect(err?.textContent).toContain('TCP Socket: 失败')

    const dnsRec = host.querySelector('[data-testid="dns-recovery-failed"]')
    expect(dnsRec?.textContent).toContain('系统 DNS 恢复失败')

    const counts = host.querySelector('[data-testid="decision-counts"]')
    expect(counts?.textContent).toBe('128 / 4096')
    expect(card.textContent).toContain('丢弃 3 条')
  })

  it('shows DNS recovered notice and imports a JSON config file via PUT /api/config', async () => {
    routes = {
      '/api/config': baseConfig,
      '/api/autostart': { enabled: false, start_minimized: false, location_trusted: true },
      '/api/stats': {
        hijacked_pids: 3,
        auto_rules_count: 1,
        tree_ready: true,
        process_count: 90,
        dns: { state: 'running', listen: '127.0.0.2:53', recovery: 'recovered' },
        interception: {
          mode: 'windivert',
          active: true,
          layers: {
            tcp_socket: true,
            tcp_network: true,
            tcp_v6: true,
            udp_socket: true,
            udp_network: true,
          },
        },
        decisions: { written: 15, dropped: 0, capacity: 4096 },
      },
    }
    await render()

    expect(host.querySelector('[data-testid="engine-interception-error"]')).toBeNull()
    expect(host.querySelector('[data-testid="dns-recovery-recovered"]')?.textContent).toContain('自动恢复')

    const input = host.querySelector<HTMLInputElement>('input[type="file"][aria-label="选择配置文件"]')!
    const imported = { version: 2, log_level: 'debug', proxy_groups: [{ id: 0, name: 'Default', type: 'socks5', host: '127.0.0.1', port: 1080 }] }
    const file = new File([JSON.stringify(imported)], 'backup.json', { type: 'application/json' })
    Object.defineProperty(file, 'text', { value: async () => JSON.stringify(imported) })
    Object.defineProperty(input, 'files', { value: [file], configurable: true })

    act(() => {
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })
    await flush()

    expect(putCalls).toHaveLength(1)
    expect(putCalls[0]).toEqual({ url: '/api/config', body: imported })
  })

  it('shows Hook mode injected and skip-reason breakdown badges', async () => {
    routes = {
      '/api/config': { ...baseConfig, interception: { mode: 'hook' } },
      '/api/autostart': { enabled: false, start_minimized: false, location_trusted: true },
      '/api/stats': {
        hijacked_pids: 5,
        auto_rules_count: 1,
        tree_ready: true,
        process_count: 80,
        dns: { state: 'off' },
        interception: {
          mode: 'hook',
          active: true,
          hook: {
            injected: 3,
            live_injected: 2,
            inject_skipped: 2,
            inject_failed: 1,
            skip_reasons: { wow64: 0, restricted: 1, signed_only: 1, open_failed: 0, failed: 1 },
          },
        },
        decisions: { written: 12, dropped: 0, capacity: 4096 },
      },
    }
    await render()

    const summary = host.querySelector('[data-testid="engine-hook-summary"]')
    expect(summary?.textContent).toContain('已注入 2')
    expect(summary?.textContent).toContain('沙盒跳过 1')
    expect(summary?.textContent).toContain('仅签名跳过 1')
    expect(summary?.textContent).toContain('注入失败 1')
    expect(summary?.textContent).not.toContain('32位跳过')
  })

  it('exports sanitized diagnostics bundle ZIP from /api/diagnostics/export', async () => {
    routes = {
      '/api/config': baseConfig,
      '/api/autostart': { enabled: false, start_minimized: false, location_trusted: true },
      '/api/stats': {
        hijacked_pids: 0,
        auto_rules_count: 0,
        tree_ready: true,
        process_count: 50,
        dns: { state: 'off' },
        interception: { mode: 'windivert', active: true },
        decisions: { written: 0, dropped: 0, capacity: 4096 },
      },
    }
    const diagCalls: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      const path = url.split('?')[0]!
      if (path === '/api/diagnostics/export') {
        diagCalls.push(path)
        return new Response(new Uint8Array([0x50, 0x4b, 0x05, 0x06]), {
          status: 200,
          headers: {
            'Content-Type': 'application/zip',
            'Content-Disposition': 'attachment; filename="proxyclaw-diagnostics-20261126-120000.zip"',
          },
        })
      }
      return new Response(JSON.stringify(routes[path] ?? {}), { status: 200 })
    }))

    const createObjectURL = vi.fn(() => 'blob:mock-diag')
    const revokeObjectURL = vi.fn()
    Object.defineProperty(URL, 'createObjectURL', { value: createObjectURL, configurable: true })
    Object.defineProperty(URL, 'revokeObjectURL', { value: revokeObjectURL, configurable: true })
    let downloadedName = ''
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      downloadedName = this.download
    })

    try {
      await render()
      const btn = host.querySelector<HTMLButtonElement>('[data-testid="export-diagnostics-btn"]')!
      expect(btn).not.toBeNull()
      act(() => { btn.click() })
      await flush()

      expect(diagCalls).toEqual(['/api/diagnostics/export'])
      expect(createObjectURL).toHaveBeenCalledTimes(1)
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock-diag')
      expect(downloadedName).toBe('proxyclaw-diagnostics-20261126-120000.zip')
    } finally {
      clickSpy.mockRestore()
    }
  })
})
