import { defineConfig } from 'electron-vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  main: {
    entry: resolve(__dirname, 'src/main/index.ts'),
    build: {
      outDir: 'out/main',
    },
  },
  preload: {
    entry: resolve(__dirname, 'src/preload/index.ts'),
    build: {
      outDir: 'out/preload',
    },
  },
  renderer: {
    root: resolve(__dirname, 'src/renderer'),
    build: {
      outDir: 'out/renderer',
      rollupOptions: {
        input: {
          index: resolve(__dirname, 'src/renderer/index.html'),
        },
      },
    },
    plugins: [react()],
    server: {
      proxy: {
        '/api': {
          target: 'http://localhost:5000',
          changeOrigin: true,
        },
      },
    },
  },
})
