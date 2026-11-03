import { useCallback, useRef, useState, type ReactNode } from 'react'

const STORAGE_KEY = 'clew-main-split'

function loadSize(fallback: number, min: number, max: number): number {
  const v = Number(localStorage.getItem(STORAGE_KEY))
  return Number.isFinite(v) && v >= min && v <= max ? v : fallback
}

/** Two-pane horizontal split; left width in percent, persisted. */
export function Split({ left, right, defaultSize = 24, min = 16, max = 45 }: {
  left: ReactNode
  right: ReactNode
  defaultSize?: number
  min?: number
  max?: number
}) {
  const [size, setSize] = useState(() => loadSize(defaultSize, min, max))
  const box = useRef<HTMLDivElement>(null)

  const onPointerDown = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    e.preventDefault()
    const handle = e.currentTarget
    handle.setPointerCapture(e.pointerId)
    let last = size
    const move = (ev: PointerEvent) => {
      const rect = box.current?.getBoundingClientRect()
      if (!rect || rect.width === 0) return
      last = Math.min(max, Math.max(min, ((ev.clientX - rect.left) / rect.width) * 100))
      setSize(last)
    }
    const up = () => {
      handle.removeEventListener('pointermove', move)
      handle.removeEventListener('pointerup', up)
      localStorage.setItem(STORAGE_KEY, String(Math.round(last * 10) / 10))
    }
    handle.addEventListener('pointermove', move)
    handle.addEventListener('pointerup', up)
  }, [size, min, max])

  return (
    <div ref={box} className="flex min-h-0 flex-1">
      <div className="flex min-h-0 min-w-0 flex-col" style={{ width: `${size}%` }}>{left}</div>
      <div
        role="separator"
        aria-orientation="vertical"
        aria-valuenow={Math.round(size)}
        onPointerDown={onPointerDown}
        className="group relative w-px shrink-0 cursor-col-resize bg-border"
      >
        <div className="absolute inset-y-0 -left-1.5 -right-1.5 group-hover:bg-primary/10" />
      </div>
      <div className="flex min-h-0 min-w-0 flex-1 flex-col">{right}</div>
    </div>
  )
}
