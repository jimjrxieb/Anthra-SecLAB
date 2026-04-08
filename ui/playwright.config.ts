import { defineConfig, devices } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || 'http://localhost:5173'; // UI (Vite or Service)
const API_URL = process.env.API_URL || 'http://localhost:8001'; // FastAPI (via port-forward)

export default defineConfig({
  testDir: './tests',
  timeout: 90_000,
  expect: { timeout: 30_000 },
  reporter: [['list'], ['html', { open: 'never' }]],
  retries: process.env.CI ? 2 : 0,
  globalSetup: './tests/global-setup.ts',
  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    actionTimeout: 20_000,
    navigationTimeout: 30_000,
    extraHTTPHeaders: { 'X-Playwright-API-Base': API_URL },
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
