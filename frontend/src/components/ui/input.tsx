import { forwardRef, type InputHTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

/** Shared field look: hairline border, accent border + soft ring on focus. */
export const fieldClass = cn(
  'rounded-lg border border-border bg-input text-foreground shadow-xs outline-none',
  'transition-[border-color,box-shadow] duration-150 hover:border-faint',
  'focus:border-primary/70 focus:ring-3 focus:ring-primary/15 focus:hover:border-primary/70',
  'disabled:pointer-events-none disabled:opacity-50',
)

export const inputClass = cn(fieldClass, 'h-8 w-full px-2.5 text-ui placeholder:text-faint')

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => <input ref={ref} className={cn(inputClass, className)} {...props} />,
)
Input.displayName = 'Input'
