// @vitest-environment jsdom
import { QueryClientProvider } from '@tanstack/react-query'
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { applyPush } from '@/api/notify'
import { createQueryClient } from '@/api/queries'
import { TooltipProvider } from '@/components/ui/tooltip'
import { ProcessTree } from './ProcessTree'

let root: Root
let host: HTMLDivElement

beforeEach(() => {
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  vi.stubGlobal('fetch', vi.fn(async () => new Response('[]', { status: 200 })))
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue(
    { x: 0, y: 0, top: 0, left: 0, right: 240, bottom: 600, width: 240, height: 600, toJSON: () => ({}) } as DOMRect)
  vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockReturnValue(600)
  vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(240)
  host = document.createElement('div')
  document.body.appendChild(host)
})

afterEach(() => {
  act(() => root.unmount())
  host.remove()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

const TREE = [
  { pid: 1, psn: 1, parent_pid: 0, name: 'explorer.exe', hijacked: false, children: [
    { pid: 10, psn: 100, parent_pid: 1, name: 'app.exe', hijacked: false, children: [
      { pid: 11, psn: 110, parent_pid: 10, name: 'child.exe', hijacked: false, children: [] },
    ] },
  ] },
  { pid: 2, psn: 2, parent_pid: 0, name: 'svc.exe', hijacked: false, children: [] },
]

const flush = () => act(async () => { await new Promise(r => setTimeout(r, 20)) })

async function mount(onSelect = vi.fn()) {
  const qc = createQueryClient()
  root = createRoot(host)
  let selected: number | undefined
  const render = () => root.render(
    <QueryClientProvider client={qc}>
      <TooltipProvider>
        <ProcessTree selectedPid={selected} onSelect={pid => { selected = pid; onSelect(pid); render() }} />
      </TooltipProvider>
    </QueryClientProvider>)
  act(render)
  act(() => applyPush(qc, { event: 'process_update', data: TREE }))
  await flush()
  return onSelect
}

const tree = () => host.querySelector<HTMLElement>('[role="tree"]')!
const items = () => [...host.querySelectorAll<HTMLElement>('[role="treeitem"]')]
const names = () => items().map(i => i.getAttribute('aria-label'))
const active = () => document.getElementById(tree().getAttribute('aria-activedescendant') ?? '')
function key(k: string) {
  act(() => { tree().dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true })) })
}

describe('ProcessTree keyboard and ARIA', () => {
  it('exposes a tree with levels, expansion and selection', async () => {
    await mount()
    expect(tree().getAttribute('aria-label')).toBe('进程树')
    expect(tree().tabIndex).toBe(0)
    expect(names()).toEqual(['explorer.exe 1', 'svc.exe 2'])
    const [explorer, svc] = items()
    expect(explorer!.getAttribute('aria-level')).toBe('1')
    expect(explorer!.getAttribute('aria-expanded')).toBe('false')
    expect(svc!.hasAttribute('aria-expanded')).toBe(false)
    expect(explorer!.getAttribute('aria-selected')).toBe('false')
    // The first row is the keyboard's starting point.
    expect(active()?.getAttribute('aria-label')).toBe('explorer.exe 1')
  })

  it('moves, expands, collapses and selects with the keyboard alone', async () => {
    const onSelect = await mount()
    key('ArrowRight')                       // expand explorer
    expect(names()).toEqual(['explorer.exe 1', 'app.exe 10', 'svc.exe 2'])
    expect(items()[0]!.getAttribute('aria-expanded')).toBe('true')
    key('ArrowRight')                       // into first child
    expect(active()?.getAttribute('aria-label')).toBe('app.exe 10')
    expect(active()?.getAttribute('aria-level')).toBe('2')
    key('ArrowRight')                       // expand app
    key('ArrowDown')
    expect(active()?.getAttribute('aria-label')).toBe('child.exe 11')
    key('ArrowLeft')                        // leaf: go to parent
    expect(active()?.getAttribute('aria-label')).toBe('app.exe 10')
    key('ArrowLeft')                        // expanded: collapse
    expect(names()).toEqual(['explorer.exe 1', 'app.exe 10', 'svc.exe 2'])
    key('End')
    expect(active()?.getAttribute('aria-label')).toBe('svc.exe 2')
    key('Home')
    expect(active()?.getAttribute('aria-label')).toBe('explorer.exe 1')
    key('ArrowUp')                          // clamped at the top
    expect(active()?.getAttribute('aria-label')).toBe('explorer.exe 1')
    key('ArrowDown')
    key('Enter')
    expect(onSelect).toHaveBeenLastCalledWith(10)
    expect(active()?.getAttribute('aria-selected')).toBe('true')
    key('End')
    key(' ')
    expect(onSelect).toHaveBeenLastCalledWith(2)
  })

  it('keeps only the active row action tabbable', async () => {
    await mount()
    const buttons = [...host.querySelectorAll<HTMLButtonElement>('button[aria-label="启用代理"]')]
    expect(buttons).toHaveLength(2)
    expect(buttons.map(b => b.tabIndex)).toEqual([0, -1])
    key('ArrowDown')
    expect(buttons.map(b => b.tabIndex)).toEqual([-1, 0])
  })
})
