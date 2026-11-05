import { forwardRef, type InputHTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

/** Shared field look (magpie): borderless filled pill, inset accent ring on focus. */
export const fieldClass = cn(
  'rounded-md border-0 bg-field text-foreground outline-none',
  'transition-[background-color,box-shadow] duration-150 hover:bg-field-hover',
  'focus:bg-field focus:ring-1 focus:ring-inset focus:ring-primary',
  'disabled:pointer-events-none disabled:opacity-50',
)

export const inputClass = cn(fieldClass, 'h-7 w-full px-2.5 text-xs placeholder:text-faint')

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => <input ref={ref} className={cn(inputClass, className)} {...props} />,
)
Input.displayName = 'Input'
