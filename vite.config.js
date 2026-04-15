import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'

export default defineConfig({
  plugins: [react()],
  base: './', // Essential for Electron
  build: {
    outDir: 'dist',
  },
  server: {
    port: 5173,
  }
})
