import { forwardRef, type InputHTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

export const inputClass = cn(
  'h-9 w-full rounded-lg border border-border bg-input px-3 text-sm text-foreground',
  'placeholder:text-muted-foreground/70 outline-none transition-colors',
  'focus:border-ring/60 focus:ring-2 focus:ring-ring/20 disabled:opacity-50',
)

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => <input ref={ref} className={cn(inputClass, className)} {...props} />,
)
Input.displayName = 'Input'
