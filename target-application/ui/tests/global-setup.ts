import { FullConfig } from '@playwright/test';
import { spawn } from 'node:child_process';

let pf: ReturnType<typeof spawn> | null = null;

async function wait(ms: number) {
  return new Promise(r => setTimeout(r, ms));
}

export default async function globalSetup(_config: FullConfig) {
  if (!process.env.API_URL) {
    // Start a port-forward to 8001 if not provided
    pf = spawn(
      'kubectl',
      ['-n', 'portfolio', 'port-forward', 'svc/portfolio-api', '8001:80'],
      {
        stdio: 'inherit',
      }
    );
    process.env.API_URL = 'http://localhost:8001';
    // give it a moment
    await wait(1500);
  }
}

export async function teardown() {
  if (pf) pf.kill('SIGINT');
}
