import { defineConfig } from 'electron-vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  main: {
    build: {
      lib: {
        entry: 'main/index.ts'
      }
    },
    resolve: {
      alias: {
        '@main': resolve('main')
      }
    }
  },
  preload: {
    build: {
      lib: {
        entry: 'preload/index.ts'
      }
    },
    plugins: []
  },
  renderer: {
    root: 'renderer',
    build: {
      rollupOptions: {
        input: resolve('renderer/index.html')
      }
    },
    resolve: {
      alias: {
        '@renderer': resolve('renderer/src')
      }
    },
    plugins: [react()]
  }
})
