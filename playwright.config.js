import { defineConfig } from '@playwright/test'
const apiPort = Number(process.env.SP_TEST_API_PORT || 5338)
const webPort = Number(process.env.SP_TEST_WEB_PORT || 5183)
if (![apiPort, webPort].every((port) => Number.isInteger(port) && port > 1024 && port <= 65535) || apiPort === webPort) throw new Error('Invalid test ports')
const python = process.env.SP_PYTHON || 'api/venv/bin/python'
export default defineConfig({
  testDir: './tests/e2e', timeout: 60000, expect: { timeout: 10000 }, workers: 2,
  use: { baseURL: process.env.PREVIEW_URL || `http://127.0.0.1:${webPort}`, extraHTTPHeaders: process.env.VERCEL_AUTOMATION_BYPASS_SECRET ? {'x-vercel-protection-bypass':process.env.VERCEL_AUTOMATION_BYPASS_SECRET} : {}, trace: process.env.PREVIEW_URL ? 'off' : 'retain-on-failure', screenshot: 'only-on-failure', permissions: ['clipboard-read', 'clipboard-write'] },
  webServer: process.env.PREVIEW_URL ? undefined : [
    { command: `${python} -m flask --app api.index run --port ${apiPort}`, url: `http://127.0.0.1:${apiPort}/api/health`, reuseExistingServer: false },
    { command: `npm run preview -- --host 127.0.0.1 --port ${webPort} --strictPort`, env: { SP_API_PORT: String(apiPort) }, url: `http://127.0.0.1:${webPort}`, reuseExistingServer: false },
  ],
})
