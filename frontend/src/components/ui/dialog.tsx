import * as DialogPrimitive from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

export function Dialog({ open, onOpenChange, title, description, children, footer, className, modalLock }: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: ReactNode
  description?: ReactNode
  children?: ReactNode
  footer?: ReactNode
  className?: string
  /** Ignore outside clicks and Escape (forms with unsaved input). */
  modalLock?: boolean
}) {
  const block = modalLock ? (e: Event) => e.preventDefault() : undefined
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fade-in fixed inset-0 z-40 bg-black/35 dark:bg-black/55" />
        <DialogPrimitive.Content
          onInteractOutside={block}
          onEscapeKeyDown={block}
          className={cn(
            'dialog-in fixed inset-0 z-50 m-auto flex h-fit max-h-[88vh] w-[calc(100vw-2rem)] max-w-md flex-col',
            'rounded-2xl border border-border bg-popover text-popover-foreground shadow-xl outline-none focus-visible:outline-none',
            className,
          )}
        >
          <div className="flex items-start justify-between gap-4 px-5 pt-4 pb-3">
            <div className="min-w-0">
              <DialogPrimitive.Title className="text-base font-semibold">{title}</DialogPrimitive.Title>
              {description
                ? <DialogPrimitive.Description className="mt-0.5 text-xs text-muted-foreground">{description}</DialogPrimitive.Description>
                : <DialogPrimitive.Description className="sr-only">{title}</DialogPrimitive.Description>}
            </div>
            <DialogPrimitive.Close aria-label="关闭" className="-mr-1 rounded-md p-1 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground">
              <X className="size-4" />
            </DialogPrimitive.Close>
          </div>
          <div className="thin-scrollbar min-h-0 flex-1 overflow-y-auto px-5 pb-4">{children}</div>
          {footer && <div className="flex items-center justify-end gap-2 rounded-b-2xl border-t border-divider bg-surface-2 px-5 py-3">{footer}</div>}
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}
