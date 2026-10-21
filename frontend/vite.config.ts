import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev proxy: the frontend talks to same-origin paths and Vite forwards them
// to the FastAPI backend, so no CORS is involved during development.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/analyze': 'http://127.0.0.1:8000',
      '/health': 'http://127.0.0.1:8000',
      '/diagnose': 'http://127.0.0.1:8000',
      '/query': 'http://127.0.0.1:8000',
      '/report': 'http://127.0.0.1:8000',
      '/jobs': 'http://127.0.0.1:8000',
    },
  },
})
