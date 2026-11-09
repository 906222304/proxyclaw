import type { ButtonHTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger'
type Size = 'sm' | 'md' | 'icon'

const variants: Record<Variant, string> = {
  primary: 'bg-primary text-primary-foreground shadow-xs hover:brightness-110 active:brightness-95',
  secondary: 'border border-border bg-card text-foreground-2 shadow-xs hover:border-faint hover:bg-surface-2 hover:text-foreground active:bg-muted',
  ghost: 'text-muted-foreground hover:bg-muted hover:text-foreground active:bg-hover',
  danger: 'bg-destructive text-danger-foreground shadow-xs hover:brightness-110 active:brightness-95',
}
const sizes: Record<Size, string> = {
  sm: 'h-control px-2.5 text-xs gap-1.5',
  md: 'h-8 px-3 text-xs gap-1.5',
  icon: 'size-control justify-center',
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: Size
}

export function Button({ variant = 'secondary', size = 'md', className, type = 'button', ...props }: ButtonProps) {
  return (
    <button
      type={type}
      className={cn(
        'inline-flex shrink-0 select-none items-center whitespace-nowrap rounded-lg font-medium',
        'transition-[background-color,border-color,color,filter,scale] duration-150 active:scale-97',
        'disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-3.5',
        // Own (non-opaque, rounded) layer: Chromium then draws grayscale AA
        // instead of ClearType, whose colour fringes made dense CJK strokes
        // (测 in 全部测速) look amber/blue at 12px.
        'aa-gray',
        variants[variant], sizes[size], className,
      )}
      {...props}
    />
  )
}
