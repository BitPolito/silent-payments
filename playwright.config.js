import { defineConfig } from '@playwright/test'
const python = process.env.SP_PYTHON || 'api/venv/bin/python'
export default defineConfig({
  testDir: './tests/e2e', timeout: 60000, expect: { timeout: 10000 }, workers: 2,
  use: { baseURL: process.env.PREVIEW_URL || 'http://127.0.0.1:5173', extraHTTPHeaders: process.env.VERCEL_AUTOMATION_BYPASS_SECRET ? {'x-vercel-protection-bypass':process.env.VERCEL_AUTOMATION_BYPASS_SECRET} : {}, trace: process.env.PREVIEW_URL ? 'off' : 'retain-on-failure', screenshot: 'only-on-failure', permissions: ['clipboard-read', 'clipboard-write'] },
  webServer: process.env.PREVIEW_URL ? undefined : [
    { command: `${python} -m flask --app api.index run --port 5328`, url: 'http://127.0.0.1:5328/api/health', reuseExistingServer: !process.env.CI },
    { command: 'npm run preview -- --host 127.0.0.1 --port 5173', url: 'http://127.0.0.1:5173', reuseExistingServer: !process.env.CI },
  ],
})
