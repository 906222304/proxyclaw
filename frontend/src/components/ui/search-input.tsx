import { Search, X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { inputClass } from './input'

export function SearchInput({ value, onChange, placeholder, className, ariaLabel }: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  className?: string
  ariaLabel?: string
}) {
  return (
    <div className={cn('relative', className)}>
      <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-faint" />
      <input
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={ariaLabel ?? placeholder?.replace(/…$/, '')}
        className={cn(inputClass, 'h-8 bg-card pl-8 pr-7 text-xs')}
      />
      {value && (
        <button
          type="button"
          aria-label="清空搜索"
          onClick={() => onChange('')}
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
        >
          <X className="size-3.5" />
        </button>
      )}
    </div>
  )
}
