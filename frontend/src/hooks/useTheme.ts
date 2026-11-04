import { useSyncExternalStore } from 'react'

const STORAGE_KEY = 'clew-theme'
const listeners = new Set<() => void>()
let dark = true

function apply() {
  document.documentElement.classList.toggle('dark', dark)
}

export function initTheme() {
  const stored = localStorage.getItem(STORAGE_KEY)
  dark = stored ? stored === 'dark' : true
  apply()
}

export function toggleTheme() {
  dark = !dark
  localStorage.setItem(STORAGE_KEY, dark ? 'dark' : 'light')
  apply()
  for (const l of listeners) l()
}

function subscribe(cb: () => void) {
  listeners.add(cb)
  return () => { listeners.delete(cb) }
}

export function useIsDark(): boolean {
  return useSyncExternalStore(subscribe, () => dark)
}
