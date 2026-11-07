// @vitest-environment jsdom
import { QueryClientProvider } from '@tanstack/react-query'
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createQueryClient } from '@/api/queries'
import { splitDir } from '@/components/ProcessContextHeader'
import { ProxiesTab } from '@/components/ProxiesTab'

const rule = { id: 'r1', name: '规则一', enabled: true, process_name: 'app.exe', cmdline_pattern: '', hack_tree: true, protocol: 'tcp', proxy_group_id: 0, proxy: { type: 'socks5', host: '127.0.0.1', port: 7890 }, dst_filter: { include_cidrs: [], exclude_cidrs: [], include_ports: [], exclude_ports: [] } }
const routes: Record<string, unknown> = {
  '/api/auto-rules': [rule],
  '/api/proxy-groups': [{ id: 0, name: '默认', host: '127.0.0.1', port: 7890, type: 'socks5', test_url: 'https://www.google.com' }],
}

let root: Root
let host: HTMLDivElement

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
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
const click = (el: Element) => act(() => { el.dispatchEvent(new MouseEvent('click', { bubbles: true, button: 0 })) })

describe('ProxiesTab', () => {
  it('calls onEditRule when a rule in an expanded group is clicked', async () => {
    const onEditRule = vi.fn()
    root = createRoot(host)
    act(() => root.render(<QueryClientProvider client={createQueryClient()}><ProxiesTab onEditRule={onEditRule} /></QueryClientProvider>))
    await flush()

    expect(host.querySelector('[data-testid="group-rules"]')).toBeNull()
    click(host.querySelector('[role="button"][aria-expanded="false"]')!)
    await flush()

    const ruleBtn = [...host.querySelectorAll('[data-testid="group-rules"] button')].find(b => b.textContent?.includes('规则一'))!
    expect(ruleBtn).toBeTruthy()
    click(ruleBtn)
    expect(onEditRule).toHaveBeenCalledTimes(1)
    expect(onEditRule.mock.calls[0]![0]).toMatchObject({ id: 'r1' })
  })
})

describe('ProxiesTab group editor', () => {
  it('blocks an out-of-range port with an inline error and sends nothing', async () => {
    root = createRoot(host)
    act(() => root.render(<QueryClientProvider client={createQueryClient()}><ProxiesTab /></QueryClientProvider>))
    await flush()
    click([...host.querySelectorAll('button')].find(b => b.textContent?.includes('新建代理组'))!)
    await flush()

    const port = document.querySelector<HTMLInputElement>('input[placeholder="7890"]')!
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(port, '70000')
      port.dispatchEvent(new Event('input', { bubbles: true }))
    })
    const create = [...document.querySelectorAll('button')].find(b => b.textContent === '创建')!
    click(create)
    await flush()

    expect(document.body.textContent).toContain('端口范围 1–65535')
    const posts = vi.mocked(fetch).mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === 'POST')
    expect(posts).toHaveLength(0)
  })
})

describe('splitDir', () => {
  it('keeps the last folder and separators out of the ellipsized head', () => {
    expect(splitDir('D:\\a\\proxyclaw\\build\\win\\')).toEqual({ head: 'D:\\a\\proxyclaw\\build', tail: '\\win\\' })
    expect(splitDir('C:\\')).toEqual({ head: '', tail: 'C:\\' })
    expect(splitDir('/usr/bin/')).toEqual({ head: '/usr', tail: '/bin/' })
    expect(splitDir('')).toEqual({ head: '', tail: '' })
  })
})
