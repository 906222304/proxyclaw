import * as DropdownMenu from '@radix-ui/react-dropdown-menu'
import { MoreHorizontal } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

export interface MenuItem {
  label: ReactNode
  icon?: ReactNode
  /** Faint trailing note, e.g. a caveat about the action. */
  hint?: ReactNode
  /** Native tooltip for the item. */
  title?: string
  onSelect: () => void
  danger?: boolean
  disabled?: boolean
}

/** A ⋯ button that opens a small action menu. */
export function MoreMenu({ items, label = '更多操作', className }: { items: MenuItem[]; label?: string; className?: string }) {
  return (
    <DropdownMenu.Root modal={false}>
      <DropdownMenu.Trigger
        aria-label={label}
        title={label}
        onClick={e => e.stopPropagation()}
        className={cn(
          'inline-flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground outline-none transition-[background-color,color,scale] duration-150',
          'hover:bg-field hover:text-foreground active:scale-97 data-[state=open]:bg-field data-[state=open]:text-foreground',
          className,
        )}
      >
        <MoreHorizontal className="size-4" />
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="end"
          sideOffset={4}
          onClick={e => e.stopPropagation()}
          className="z-50 min-w-32 rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-lg pop-in"
        >
          {items.map((it, i) => (
            <DropdownMenu.Item
              key={i}
              disabled={it.disabled}
              onSelect={it.onSelect}
              title={it.title}
              className={cn(
                'flex h-7 cursor-default items-center gap-2 rounded-md px-2 text-xs outline-none data-[disabled]:opacity-50 [&_svg]:size-3.5',
                it.danger ? 'text-destructive data-[highlighted]:bg-destructive-soft' : 'data-[highlighted]:bg-field',
              )}
            >
              {it.icon}
              {it.label}
              {it.hint && <span className="ml-auto pl-4 text-2xs text-faint">{it.hint}</span>}
            </DropdownMenu.Item>
          ))}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}
