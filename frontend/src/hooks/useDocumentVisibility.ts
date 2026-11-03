import { useSyncExternalStore } from 'react'

// document.visibilityState reflects WebView2 IsVisible after the host calls
// put_IsVisible on minimize / restore / tray hide / tray show
// (webview_app::set_visible). Polls pause on their own (TanStack Query's
// focusManager listens to the same event); this hook is for the few places
// that react to the transition itself, e.g. the push replay handshake.
function subscribe(cb: () => void) {
  document.addEventListener('visibilitychange', cb)
  return () => document.removeEventListener('visibilitychange', cb)
}

export function useDocumentVisibility(): boolean {
  return useSyncExternalStore(
    subscribe,
    () => document.visibilityState !== 'hidden',
    () => true,
  )
}
