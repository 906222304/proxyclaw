// One active request; start the next interval only after it settles.
// Generations also reject stale results when a view changes or is hidden.
export function createAsyncPoller<T>(
  intervalMs: number,
  fetchData: (signal: AbortSignal) => Promise<T>,
  apply: (data: T) => void,
) {
  let enabled = false
  let generation = 0
  let timer: ReturnType<typeof setTimeout> | null = null
  let controller: AbortController | null = null

  function cancel() {
    ++generation
    if (timer !== null) clearTimeout(timer)
    timer = null
    controller?.abort()
    controller = null
  }

  async function run() {
    const current = ++generation
    const request = new AbortController()
    controller = request
    try {
      const data = await fetchData(request.signal)
      if (enabled && current === generation && !request.signal.aborted) apply(data)
    } catch {
      // A temporary backend failure is retried on the next interval.
    } finally {
      // Promise.all may reject before a sibling HTTP request finishes.
      request.abort()
      if (enabled && current === generation) {
        controller = null
        timer = setTimeout(() => { timer = null; void run() }, intervalMs)
      }
    }
  }

  return {
    start() {
      if (enabled) return
      enabled = true
      void run()
    },
    stop() {
      enabled = false
      cancel()
    },
    refresh() {
      if (!enabled) return
      cancel()
      void run()
    },
  }
}
