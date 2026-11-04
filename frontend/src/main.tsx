import { QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { startNotifications } from '@/api/notify'
import { createQueryClient } from '@/api/queries'
import { initTheme } from '@/hooks/useTheme'
import App from './App'
import './style.css'

initTheme()
const queryClient = createQueryClient()
startNotifications(queryClient)

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
)
