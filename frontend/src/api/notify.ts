import type { QueryClient } from '@tanstack/react-query'
import { queryKeys } from './queryKeys'
import type { ProcessInfo } from './types'

// Backend->frontend push channel. The C++ host (webview_app) uses
// ICoreWebView2::PostWebMessageAsJson; each message arrives in JS as a
// `{ event, data }` envelope on `window.chrome.webview`'s `message` event.
// The full process tree is delivered inside every `process_update` push, so
// the frontend never polls /api/processes.
//
// This module owns no copy of server data: a push only writes into the
// TanStack Query cache (setQueryData) or marks queries stale
// (invalidateQueries). Components read the cache through useQuery.

declare global {
  interface Window {
    chrome?: {
      webview?: {
        postMessage(msg: unknown): void
        addEventListener(type: 'message', listener: (e: MessageEvent) => void): void
        removeEventListener?(type: 'message', listener: (e: MessageEvent) => void): void
      }
    }
  }
}

export interface NotificationEvents {
  process_update: ProcessInfo[]
  auto_rule_changed: { action: string }
}

export type NotificationEvent = keyof NotificationEvents

interface Envelope<T extends NotificationEvent = NotificationEvent> {
  event: T
  data: NotificationEvents[T]
}

/** Apply one push envelope to the query cache. Exported for tests. */
export function applyPush(queryClient: QueryClient, envelope: Envelope): void {
  switch (envelope.event) {
    case 'process_update':
      queryClient.setQueryData(queryKeys.processTree, envelope.data as ProcessInfo[])
      break
    case 'auto_rule_changed':
      // Match counts and the rule list itself changed server-side.
      void queryClient.invalidateQueries({ queryKey: queryKeys.autoRules })
      void queryClient.invalidateQueries({ queryKey: queryKeys.stats })
      break
  }
}

// --- connection flag (client state, not server data) ---
let connected = false
const listeners = new Set<() => void>()

export function subscribeConnected(cb: () => void): () => void {
  listeners.add(cb)
  return () => { listeners.delete(cb) }
}
export function getConnected(): boolean {
  return connected
}

/** Ask the backend to replay the current snapshot (initial sync / restore). */
export function postReady(): void {
  window.chrome?.webview?.postMessage({ type: 'ready' })
}

let started: QueryClient | null = null

/**
 * Wire the WebView2 push channel into `queryClient`. Idempotent. Returns
 * false when not running inside WebView2 (e.g. Vite dev server opened in a
 * normal browser), in which case the tree stays empty.
 */
export function startNotifications(queryClient: QueryClient): boolean {
  if (started) return connected
  started = queryClient

  // Debug bridge for CDP-driven tests (e.g. Playwright): returns the
  // current pushed state as plain JSON. Always on; the WebView2 host is
  // in-process, so there is no user-facing surface to leak.
  ;(window as unknown as { __clew_debug: unknown }).__clew_debug = {
    tree: () => queryClient.getQueryData<ProcessInfo[]>(queryKeys.processTree) ?? [],
    connected: () => connected,
  }

  const wv = window.chrome?.webview
  if (!wv) {
    console.warn('[notify] not running in WebView2; push channel unavailable')
    return false
  }

  wv.addEventListener('message', (event) => {
    const env = (event as MessageEvent).data as Envelope | null
    if (!env || typeof env !== 'object' || typeof env.event !== 'string') return
    try { applyPush(queryClient, env) } catch { /* one bad message must not kill the channel */ }
  })

  // Tell the backend we're ready. webview_app::on_ready_ then triggers
  // process_projection::replay_to_frontend, which posts the current snapshot.
  postReady()
  connected = true
  for (const l of listeners) l()
  return true
}

/** Test-only: forget the started client so a test can start again. */
export function resetNotificationsForTest(): void {
  started = null
  connected = false
}
