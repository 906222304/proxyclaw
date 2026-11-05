import * as SwitchPrimitive from '@radix-ui/react-switch'
import { cn } from '@/lib/utils'

export function Switch({ className, ...props }: SwitchPrimitive.SwitchProps) {
  return (
    <SwitchPrimitive.Root
      className={cn(
        'peer inline-flex h-[18px] w-8 shrink-0 items-center rounded-full p-0.5 transition-colors duration-150',
        'bg-faint data-[state=checked]:bg-primary hover:brightness-[1.04]',
        'disabled:cursor-not-allowed disabled:opacity-50',
        className,
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb className="block size-3.5 rounded-full bg-white shadow-[0_1px_2px_rgb(0_0_0/.25)] transition-transform duration-200 ease-out data-[state=checked]:translate-x-3.5" />
    </SwitchPrimitive.Root>
  )
}
