import { useCallback, useRef, useState, type ReactNode } from 'react'

const STORAGE_KEY = 'proxyclaw-sidebar-px'

function loadSize(fallback: number, min: number, max: number): number {
  const v = Number(localStorage.getItem(STORAGE_KEY))
  return Number.isFinite(v) && v >= min && v <= max ? v : fallback
}

/**
 * Sidebar + content split. The sidebar has a fixed pixel width (persisted)
 * and no border; the handle is an invisible hit area that tints on hover.
 */
export function Split({ left, right, defaultSize = 240, min = 200, max = 360 }: {
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
      last = Math.round(Math.min(max, Math.max(min, ev.clientX - rect.left)))
      setSize(last)
    }
    const up = () => {
      handle.removeEventListener('pointermove', move)
      handle.removeEventListener('pointerup', up)
      localStorage.setItem(STORAGE_KEY, String(last))
    }
    handle.addEventListener('pointermove', move)
    handle.addEventListener('pointerup', up)
  }, [size, min, max])

  return (
    <div ref={box} className="flex min-h-0 flex-1">
      <div className="flex min-h-0 shrink-0 flex-col" style={{ width: size }}>{left}</div>
      <div
        role="separator"
        aria-orientation="vertical"
        aria-valuenow={size}
        onPointerDown={onPointerDown}
        className="group relative w-px shrink-0 cursor-col-resize"
      >
        <div className="absolute inset-y-0 -left-1 -right-1 transition-colors group-hover:bg-primary/15" />
      </div>
      <div className="flex min-h-0 min-w-0 flex-1 flex-col">{right}</div>
    </div>
  )
}
