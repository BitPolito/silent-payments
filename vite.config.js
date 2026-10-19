import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${process.env.SP_API_PORT || '5328'}`,
        changeOrigin: true,
        secure: false,
      },
    },
  },
})
