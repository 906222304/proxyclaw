import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  build: {
    rollupOptions: {
      // zod's sources carry /*#__PURE__*/ comments in positions Rollup
      // ignores; the warning is noise.
      onwarn(warning, warn) {
        if (warning.code === 'INVALID_ANNOTATION') return
        warn(warning)
      },
      output: {
        // React + the small UI libraries form one cacheable vendor chunk.
        // CodeMirror is excluded so it stays in the lazily loaded JSON editor
        // chunk and is fetched only when the editor opens.
        manualChunks(id) {
          if (!id.includes('node_modules')) return
          if (/[\\/](@codemirror|@lezer|crelt|style-mod|w3c-keyname)[\\/]/.test(id)) return
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
