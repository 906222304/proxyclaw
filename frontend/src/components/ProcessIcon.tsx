import { useQuery } from '@tanstack/react-query'
import { Monitor } from 'lucide-react'
import { processIconQuery } from '@/api/queries'
import { cn } from '@/lib/utils'

/**
 * The exe's icon, or a generic monitor glyph while loading and when the
 * backend answers 204 (no extractable icon). With `pid` the backend reads
 * that process's image path, so two exes with the same name get their own
 * icons; without it (rules) any running exe of that name is used.
 */
export function ProcessIcon({ name, pid, psn, className }: { name: string; pid?: number; psn?: number; className?: string }) {
  const { data: src } = useQuery(processIconQuery(name, pid, psn))
  return src
    ? <img src={src} alt="" className={cn('shrink-0', className)} />
    : <Monitor aria-hidden className={cn('shrink-0 text-muted-foreground', className)} />
}
