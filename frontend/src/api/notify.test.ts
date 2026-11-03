// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { applyPush, getConnected, resetNotificationsForTest, startNotifications } from './notify'
import { createQueryClient } from './queries'
import { queryKeys } from './queryKeys'
import type { ProcessInfo } from './types'

const tree: ProcessInfo[] = [{ pid: 1, parent_pid: 0, name: 'a.exe', hijacked: false, children: [] }]

describe('push channel', () => {
  afterEach(() => {
    resetNotificationsForTest()
    delete window.chrome
  })

  it('process_update writes the tree into the query cache', () => {
    const qc = createQueryClient()
    applyPush(qc, { event: 'process_update', data: tree })
    expect(qc.getQueryData(queryKeys.processTree)).toBe(tree)
  })

  it('auto_rule_changed invalidates rules and stats instead of copying data', async () => {
    const qc = createQueryClient()
    qc.setQueryData(queryKeys.autoRules, [])
    qc.setQueryData(queryKeys.stats, { hijacked_pids: 0, auto_rules_count: 0 })
    const spy = vi.spyOn(qc, 'invalidateQueries')
    applyPush(qc, { event: 'auto_rule_changed', data: { action: 'update' } })
    expect(spy.mock.calls.map(c => c[0]?.queryKey)).toEqual([queryKeys.autoRules, queryKeys.stats])
    expect(qc.getQueryState(queryKeys.autoRules)?.isInvalidated).toBe(true)
  })

  it('wires WebView2 messages, sends the ready handshake and exposes the test bridge', () => {
    let listener: ((e: MessageEvent) => void) | undefined
    const postMessage = vi.fn()
    window.chrome = {
      webview: {
        postMessage,
        addEventListener: (_t, l) => { listener = l },
      },
    }
    const qc = createQueryClient()
    expect(startNotifications(qc)).toBe(true)
    expect(postMessage).toHaveBeenCalledWith({ type: 'ready' })
    expect(getConnected()).toBe(true)

    listener!(new MessageEvent('message', { data: { event: 'process_update', data: tree } }))
    listener!(new MessageEvent('message', { data: 'garbage' }))
    const bridge = (window as unknown as { __clew_debug: { tree: () => unknown; connected: () => boolean } }).__clew_debug
    expect(bridge.tree()).toEqual(tree)
    expect(bridge.connected()).toBe(true)
  })

  it('reports not connected outside WebView2', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(startNotifications(createQueryClient())).toBe(false)
    expect(getConnected()).toBe(false)
    warn.mockRestore()
  })
})
