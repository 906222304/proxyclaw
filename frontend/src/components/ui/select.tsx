import * as SelectPrimitive from '@radix-ui/react-select'
import { Check, ChevronDown } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

export interface SelectOption {
  value: string
  label: ReactNode
}

export function Select({ value, onValueChange, options, placeholder, id, className, display, ariaLabel }: {
  value: string
  onValueChange: (v: string) => void
  options: SelectOption[]
  placeholder?: string
  id?: string
  className?: string
  /** Custom trigger content; defaults to the selected option's label. */
  display?: ReactNode
  ariaLabel?: string
}) {
  return (
    <SelectPrimitive.Root value={value} onValueChange={onValueChange}>
      <SelectPrimitive.Trigger
        id={id}
        aria-label={ariaLabel}
        className={cn(
          'inline-flex h-9 w-full items-center justify-between gap-2 rounded-lg border border-border bg-input px-3 text-sm',
          'outline-none focus:border-ring/60 focus:ring-2 focus:ring-ring/20 data-[placeholder]:text-muted-foreground',
          className,
        )}
      >
        {display ?? <SelectPrimitive.Value placeholder={placeholder} />}
        <SelectPrimitive.Icon><ChevronDown className="size-4 text-muted-foreground" /></SelectPrimitive.Icon>
      </SelectPrimitive.Trigger>
      <SelectPrimitive.Portal>
        <SelectPrimitive.Content
          position="popper"
          sideOffset={4}
          className="z-50 max-h-72 min-w-[var(--radix-select-trigger-width)] overflow-hidden rounded-lg border border-border bg-popover text-popover-foreground shadow-lg"
        >
          <SelectPrimitive.Viewport className="p-1">
            {options.map(o => (
              <SelectPrimitive.Item
                key={o.value}
                value={o.value}
                className="relative flex cursor-pointer select-none items-center rounded-md py-1.5 pl-7 pr-2 text-sm outline-none data-[highlighted]:bg-muted"
              >
                <SelectPrimitive.ItemIndicator className="absolute left-2"><Check className="size-3.5" /></SelectPrimitive.ItemIndicator>
                <SelectPrimitive.ItemText>{o.label}</SelectPrimitive.ItemText>
              </SelectPrimitive.Item>
            ))}
          </SelectPrimitive.Viewport>
        </SelectPrimitive.Content>
      </SelectPrimitive.Portal>
    </SelectPrimitive.Root>
  )
}
