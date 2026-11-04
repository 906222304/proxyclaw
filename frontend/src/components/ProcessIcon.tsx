import { useQuery } from '@tanstack/react-query'
import { Monitor } from 'lucide-react'
import { processIconQuery } from '@/api/queries'
import { cn } from '@/lib/utils'

/**
 * The exe's icon, or a generic monitor glyph while loading and when the
 * backend answers 204 (no extractable icon).
 */
export function ProcessIcon({ name, className }: { name: string; className?: string }) {
  const { data: src } = useQuery(processIconQuery(name))
  return src
    ? <img src={src} alt="" className={cn('shrink-0', className)} />
    : <Monitor aria-hidden className={cn('shrink-0 text-muted-foreground', className)} />
}
