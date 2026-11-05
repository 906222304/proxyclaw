import type { ButtonHTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger'
type Size = 'sm' | 'md' | 'icon'

const variants: Record<Variant, string> = {
  primary: 'bg-primary text-primary-foreground shadow-xs hover:brightness-[1.08] active:brightness-95',
  secondary: 'border border-border bg-card text-foreground-2 shadow-xs hover:border-faint hover:bg-surface-2 hover:text-foreground active:bg-muted',
  ghost: 'text-muted-foreground hover:bg-muted hover:text-foreground active:bg-hover',
  danger: 'bg-destructive text-white shadow-xs hover:brightness-[1.08] active:brightness-95 dark:text-[#2a1214]',
}
const sizes: Record<Size, string> = {
  sm: 'h-7 px-2.5 text-xs gap-1.5',
  md: 'h-8 px-3.5 text-ui gap-1.5',
  icon: 'size-7 justify-center',
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
        'transition-[background-color,border-color,color,filter] duration-150',
        'disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-3.5',
        variants[variant], sizes[size], className,
      )}
      {...props}
    />
  )
}
