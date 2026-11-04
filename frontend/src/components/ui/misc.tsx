import type { HTMLAttributes, ReactNode } from 'react'
import { cn } from '@/lib/utils'

type Tone = 'neutral' | 'green' | 'blue' | 'amber' | 'violet' | 'red'
const tones: Record<Tone, string> = {
  neutral: 'bg-muted text-muted-foreground',
  green: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400',
  blue: 'bg-sky-500/10 text-sky-700 dark:text-sky-400',
  amber: 'bg-amber-500/10 text-amber-700 dark:text-amber-400',
  violet: 'bg-violet-500/10 text-violet-700 dark:text-violet-400',
  red: 'bg-red-500/10 text-red-700 dark:text-red-400',
}

export function Badge({ tone = 'neutral', className, ...props }: HTMLAttributes<HTMLSpanElement> & { tone?: Tone }) {
  return (
    <span
      className={cn('inline-flex h-5 shrink-0 items-center rounded-md px-1.5 text-[11px] font-medium', tones[tone], className)}
      {...props}
    />
  )
}

/** A rounded group of rows (magpie-style settings list). */
export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('rounded-xl border border-border bg-card', className)} {...props} />
}

export function Row({ title, description, children, className }: {
  title: ReactNode
  description?: ReactNode
  children?: ReactNode
  className?: string
}) {
  return (
    <div className={cn('flex items-center justify-between gap-6 px-4 py-3.5', className)}>
      <div className="min-w-0">
        <div className="text-sm font-medium">{title}</div>
        {description && <div className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{description}</div>}
      </div>
      {children != null && <div className="flex shrink-0 items-center gap-2">{children}</div>}
    </div>
  )
}

export function SectionTitle({ children, hint }: { children: ReactNode; hint?: ReactNode }) {
  return (
    <div className="mb-2 px-1">
      <h2 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{children}</h2>
      {hint && <p className="mt-0.5 text-xs text-muted-foreground/80">{hint}</p>}
    </div>
  )
}

export function Segmented<T extends string>({ value, onChange, options, className }: {
  value: T
  onChange: (v: T) => void
  options: { value: T; label: ReactNode }[]
  className?: string
}) {
  return (
    <div role="radiogroup" className={cn('inline-flex shrink-0 rounded-lg bg-muted p-0.5', className)}>
      {options.map(o => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={cn(
            'flex-1 whitespace-nowrap rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
            value === o.value ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground',
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
        'flex size-4 shrink-0 items-center justify-center rounded border transition-colors',
        checked || indeterminate ? 'border-primary bg-primary text-primary-foreground' : 'border-muted-foreground/40 hover:border-primary',
      )}
    >
      {checked && <svg viewBox="0 0 24 24" className="size-3" fill="none" stroke="currentColor" strokeWidth={3}><path d="M5 13l4 4L19 7" strokeLinecap="round" strokeLinejoin="round" /></svg>}
      {!checked && indeterminate && <svg viewBox="0 0 24 24" className="size-3" fill="none" stroke="currentColor" strokeWidth={3}><path d="M5 12h14" strokeLinecap="round" /></svg>}
    </button>
  )
}

export function EmptyState({ icon, title, hint }: { icon?: ReactNode; title: ReactNode; hint?: ReactNode }) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-2 px-8 py-16 text-center">
      {icon && <div className="mb-2 text-muted-foreground/30 [&_svg]:size-10">{icon}</div>}
      <p className="text-sm text-muted-foreground">{title}</p>
      {hint && <p className="max-w-sm text-xs text-muted-foreground/70">{hint}</p>}
    </div>
  )
}

export function Label({ htmlFor, children, hint }: { htmlFor?: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <label htmlFor={htmlFor} className="flex items-center gap-1.5 text-xs font-medium text-foreground/80">
      {children}
      {hint}
    </label>
  )
}
