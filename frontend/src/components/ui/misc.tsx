import { CircleHelp } from 'lucide-react'
import type { CSSProperties, HTMLAttributes, ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { Tooltip } from './tooltip'

type Tone = 'neutral' | 'green' | 'blue' | 'amber' | 'violet' | 'red'
const tones: Record<Tone, string> = {
  neutral: 'bg-muted text-muted-foreground',
  green: 'bg-success-soft text-success',
  blue: 'bg-info-soft text-info',
  amber: 'bg-warning-soft text-warning',
  violet: 'bg-violet-soft text-violet',
  red: 'bg-destructive-soft text-destructive',
}

export function Badge({ tone = 'neutral', className, ...props }: HTMLAttributes<HTMLSpanElement> & { tone?: Tone }) {
  return (
    <span
      className={cn('inline-flex h-4.5 shrink-0 items-center rounded-sm px-1.5 text-2xs font-medium leading-none', tones[tone], className)}
      {...props}
    />
  )
}

/** A rounded group of rows (magpie-style settings list). */
export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('overflow-hidden rounded-xl border border-border bg-card', className)} {...props} />
}

export function Row({ title, description, hint, children, className }: {
  title: ReactNode
  description?: ReactNode
  /** Longer caveat, shown in a tooltip behind a ? icon next to the title. */
  hint?: ReactNode
  children?: ReactNode
  className?: string
}) {
  return (
    <div className={cn('flex min-h-12 items-center justify-between gap-6 px-4 py-2', className)}>
      <div className="min-w-0">
        <div className="flex items-center gap-1.5 text-sm font-medium">
          {title}
          {hint && (
            <Tooltip content={hint}>
              <span tabIndex={0} aria-label="说明" className="text-faint hover:text-muted-foreground"><CircleHelp className="size-3.5" /></span>
            </Tooltip>
          )}
        </div>
        {description && <div className="mt-0.5 truncate text-2xs text-muted-foreground">{description}</div>}
      </div>
      {children != null && <div className="flex shrink-0 items-center gap-2">{children}</div>}
    </div>
  )
}

export function SectionTitle({ children, hint }: { children: ReactNode; hint?: ReactNode }) {
  return (
    <div className="mb-1.5 px-1">
      <h2 className="text-2xs font-semibold text-muted-foreground">{children}</h2>
      {hint && <p className="mt-0.5 text-2xs text-muted-foreground">{hint}</p>}
    </div>
  )
}

/** Trackless segmented control: only the active option gets a thumb. */
export function Segmented<T extends string>({ value, onChange, options, className, size = 'md' }: {
  value: T
  onChange: (v: T) => void
  options: { value: T; label: ReactNode }[]
  className?: string
  size?: 'sm' | 'md'
}) {
  return (
    <div role="radiogroup" className={cn('aa-gray inline-flex shrink-0 gap-0.5', size === 'sm' ? 'h-6' : 'h-control', className)}>
      {options.map(o => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={cn(
            'flex-1 whitespace-nowrap rounded-md transition-[background-color,color,box-shadow,scale] duration-150 active:scale-97',
            size === 'sm' ? 'px-2 text-2xs' : 'px-2.5 text-xs',
            value === o.value ? 'bg-card font-medium text-foreground shadow-sm dark:bg-hover' : 'text-muted-foreground hover:bg-field hover:text-foreground-2',
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

export function Checkbox({ checked, indeterminate, onChange, label }: {
  checked: boolean
  indeterminate?: boolean
  onChange: () => void
  label: string
}) {
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={indeterminate ? 'mixed' : checked}
      aria-label={label}
      onClick={e => { e.stopPropagation(); onChange() }}
      className={cn(
        'flex size-3.5 shrink-0 items-center justify-center rounded-sm border transition-colors duration-150',
        checked || indeterminate ? 'border-primary bg-primary text-primary-foreground' : 'border-faint bg-card hover:border-muted-foreground',
      )}
    >
      {checked && <svg viewBox="0 0 24 24" className="size-3" fill="none" stroke="currentColor" strokeWidth={3}><path d="M5 13l4 4L19 7" strokeLinecap="round" strokeLinejoin="round" /></svg>}
      {!checked && indeterminate && <svg viewBox="0 0 24 24" className="size-3" fill="none" stroke="currentColor" strokeWidth={3}><path d="M5 12h14" strokeLinecap="round" /></svg>}
    </button>
  )
}

export function EmptyState({ icon, title, hint }: { icon?: ReactNode; title: ReactNode; hint?: ReactNode }) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-1 px-5 py-9 text-center">
      {icon && (
        <div className="mb-3 flex size-11 items-center justify-center rounded-xl bg-muted text-muted-foreground [&_svg]:size-5">{icon}</div>
      )}
      <p className="text-xs font-medium text-foreground-2">{title}</p>
      {hint && <p className="max-w-sm text-2xs text-muted-foreground">{hint}</p>}
    </div>
  )
}

/** Shimmering placeholder rows for first loads. */
export function Skeleton({ className, style }: { className?: string; style?: CSSProperties }) {
  return <span aria-hidden className={cn('skeleton h-3', className)} style={style} />
}

export function ListSkeleton({ rows = 4, className }: { rows?: number; className?: string }) {
  return (
    <div role="status" aria-label="加载中" className={cn('divide-y divide-divider overflow-hidden rounded-xl border border-border bg-card', className)}>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex h-12 items-center gap-3 px-4">
          <Skeleton className="size-4 rounded-md" />
          <div className="flex flex-1 flex-col gap-1.5">
            <Skeleton className="h-2.5" style={{ width: `${46 - (i % 3) * 9}%` }} />
            <Skeleton className="h-2 w-1/4" />
          </div>
        </div>
      ))}
    </div>
  )
}

export function Label({ htmlFor, children, hint }: { htmlFor?: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <label htmlFor={htmlFor} className="flex items-center gap-1.5 text-xs font-medium text-foreground-2">
      {children}
      {hint}
    </label>
  )
}
