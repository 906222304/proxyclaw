import { toast } from 'sonner'
import { errorText } from './utils'

// Replaces the old status-bar bus: transient feedback goes to sonner toasts.
export function pushError(e: unknown, prefix?: string) {
  const msg = errorText(e)
  toast.error(prefix ? `${prefix}：${msg}` : msg)
}

export function pushSuccess(text: string) {
  toast.success(text)
}
