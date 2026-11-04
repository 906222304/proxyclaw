// @vitest-environment jsdom
import { QueryClientProvider } from '@tanstack/react-query'
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { applyPush } from '@/api/notify'
import { createQueryClient } from '@/api/queries'
import App from './App'

// Smoke test: the whole app mounts, renders pushed data and switches tabs
// without runtime errors. Layout is not measurable in jsdom.

const routes: Record<string, unknown> = {
  '/api/stats': { hijacked_pids: 1, auto_rules_count: 1 },
  '/api/tcp': [{ pid: 10, local_ip: '127.0.0.1', local_port: 5000, remote_ip: '1.2.3.4', remote_port: 443, state: 'ESTABLISHED', dest: '', hijacked: true, pid_alive: false, proxy_status: 'IGNORED', route_reason: 'rule_exclude', process_name: 'app.exe' }],
  '/api/udp': [],
  '/api/auto-rules': [{ id: 'r1', name: '规则一', enabled: true, process_name: 'app.exe', cmdline_pattern: '', hack_tree: true, protocol: 'tcp', proxy_group_id: 0, proxy: { type: 'socks5', host: '127.0.0.1', port: 7890 }, dst_filter: { include_cidrs: [], exclude_cidrs: [], include_ports: [], exclude_ports: [] } }],
  '/api/proxy-groups': [{ id: 0, name: '默认', host: '127.0.0.1', port: 7890, type: 'socks5', test_url: 'https://www.google.com' }],
  '/api/config': { ui: { close_to_tray: true }, log_level: 'info', dns: { enabled: false } },
  '/api/autostart': { enabled: false, start_minimized: false },
  '/api/processes/10/detail': { pid: 10, parent_pid: 1, name: 'app.exe', hijacked: true, cmdline: '"C:\\App\\app.exe" --flag', image_path: 'C:\\App\\app.exe' },
}

let root: Root
let host: HTMLDivElement

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  vi.stubGlobal('matchMedia', (q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }))
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    const path = url.split('?')[0]!
    return new Response(JSON.stringify(routes[path] ?? {}), { status: 200 })
  }))
  // Give the virtualised lists a viewport to fill.
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

function click(el: Element) {
  act(() => {
    el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, button: 0 }))
    el.dispatchEvent(new MouseEvent('click', { bubbles: true, button: 0 }))
  })
}

describe('App', () => {
  it('mounts, shows pushed processes and connections, and switches tabs', async () => {
    const qc = createQueryClient()
    root = createRoot(host)
    act(() => root.render(<QueryClientProvider client={qc}><App /></QueryClientProvider>))
    act(() => applyPush(qc, {
      event: 'process_update',
      data: [{ pid: 1, parent_pid: 0, name: 'explorer.exe', hijacked: false, children: [
        { pid: 10, parent_pid: 1, name: 'app.exe', hijacked: true, hijack_source: 'manual', children: [] },
      ] }],
    }))
    await flush()

    const text = () => document.body.textContent ?? ''
    expect(text()).toContain('网络活动')
    expect(text()).toContain('explorer.exe')
    expect(text()).toContain('全部进程')
    // Connection row: Chinese labels and the dead-process styling.
    expect(text()).toContain('1.2.3.4:443')
    expect(text()).toContain('已忽略')
    expect(host.querySelector('[role="row"].line-through')).not.toBeNull()

    // Expand explorer.exe and select the child.
    const chevron = [...host.querySelectorAll('span')].find(s => s.querySelector('svg') && s.className.includes('w-3.5'))!
    click(chevron)
    await flush()
    const child = [...host.querySelectorAll('[title]')].find(e => e.getAttribute('title') === 'app.exe')!
    expect(child).toBeTruthy()
    click(child)
    await flush()
    expect(text()).toContain('PID 10')
    expect(text()).toContain('--flag')

    for (const [label, expected] of [['规则', '规则一'], ['代理', 'socks5://127.0.0.1:7890'], ['设置', '关闭窗口后保持后台运行']] as const) {
      const tab = [...host.querySelectorAll('[role="tab"]')].find(t => t.textContent?.startsWith(label))!
      click(tab)
      await flush()
      expect(text()).toContain(expected)
      if (label === '规则') {
        // The shared rule editor opens with an empty form; save is disabled.
        click([...host.querySelectorAll('button')].find(b => b.textContent?.includes('添加规则'))!)
        await flush()
        const save = [...document.querySelectorAll('button')].find(b => b.textContent === '保存规则')!
        expect(text()).toContain('进程匹配')
        expect(save.disabled).toBe(true)
        click([...document.querySelectorAll('button')].find(b => b.textContent === '取消')!)
        await flush()
        expect(text()).not.toContain('进程匹配')
      }
    }
  })
})
