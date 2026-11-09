// @vitest-environment jsdom
import { QueryClientProvider } from '@tanstack/react-query'
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createQueryClient } from '@/api/queries'
import { ConfigEditor } from '@/components/ConfigEditor'
import { TooltipProvider } from '@/components/ui/tooltip'

// Autostart runs ProxyClaw elevated without UAC; the settings page must not
// offer it from a user-writable folder and must flag an existing unsafe task.

let routes: Record<string, unknown>
let root: Root
let host: HTMLDivElement

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  vi.stubGlobal('matchMedia', (q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }))
  vi.stubGlobal('fetch', vi.fn(async (url: string) =>
    new Response(JSON.stringify(routes[url.split('?')[0]!] ?? {}), { status: 200 })))
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
  act(() => root.render(<QueryClientProvider client={createQueryClient()}><TooltipProvider><ConfigEditor /></TooltipProvider></QueryClientProvider>))
  await flush()
}

const autostartSwitch = () => host.querySelector<HTMLButtonElement>('[role="switch"][aria-label="登录 Windows 后自动启动"]')!

describe('autostart location safety', () => {
  const config = { ui: { close_to_tray: true }, log_level: 'info', dns: { enabled: false } }

  it('disables enabling from a user-writable folder and explains why', async () => {
    routes = {
      '/api/config': config,
      '/api/autostart': { enabled: false, start_minimized: false, location_trusted: false, location_issue: 'D:\\tools can be modified by non-administrators' },
    }
    await render()
    expect(autostartSwitch().disabled).toBe(true)
    const alert = host.querySelector('[data-testid="autostart-unsafe"]')
    expect(alert?.textContent).toContain('Program Files')
    expect(alert?.textContent).toContain('D:\\tools')
  })

  it('flags an existing task that points at an unsafe folder but lets the user turn it off', async () => {
    routes = {
      '/api/config': config,
      '/api/autostart': { enabled: true, start_minimized: false, location_trusted: false, task_trusted: false, task_issue: 'C:\\Users\\me\\Downloads is writable' },
    }
    await render()
    expect(autostartSwitch().disabled).toBe(false)
    const alert = host.querySelector('[data-testid="autostart-unsafe"]')
    expect(alert?.textContent).toContain('提权风险')
    expect(alert?.textContent).toContain('Downloads')
  })

  it('shows no warning for a protected install', async () => {
    routes = {
      '/api/config': config,
      '/api/autostart': { enabled: true, start_minimized: false, location_trusted: true, task_trusted: true, task_matches_exe: true },
    }
    await render()
    expect(autostartSwitch().disabled).toBe(false)
    expect(host.querySelector('[data-testid="autostart-unsafe"]')).toBeNull()
  })
})
