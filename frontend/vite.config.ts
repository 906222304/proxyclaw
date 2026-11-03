import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: [
      { find: '@', replacement: path.resolve(__dirname, './src') },
      // monaco-editor vendors its own DOMPurify copy (3.4.15, known XSS
      // advisories). Point Monaco's sanitizer at the patched npm package.
      { find: /^\.\/dompurify\/dompurify\.js$/, replacement: 'dompurify' },
    ],
  },
  build: {
    rollupOptions: {
      output: {
        // Keep the eagerly loaded app small and cache-friendly: split the
        // large UI libraries into their own vendor chunks. Monaco stays out of
        // these groups so it remains in the lazily loaded editor chunks.
        manualChunks(id) {
          if (!id.includes('node_modules') || id.includes('monaco-editor')) return
          if (id.includes('ag-grid')) return 'vendor-grid'
          if (id.includes('lucide-vue-next')) return 'vendor-icons'
          return 'vendor'
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:18080',
        changeOrigin: true,
      },
    },
  },
})
