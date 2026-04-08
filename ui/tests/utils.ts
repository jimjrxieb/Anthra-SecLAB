import { Page, Locator } from '@playwright/test';

export function byDev(page: Page, name: string): Locator {
  return page.locator(`[data-dev="${name}"]`);
}

export async function hookConsoleAndNetwork(page: Page) {
  page.on('console', msg => {
    if (['error', 'warning'].includes(msg.type())) {
      // SECURITY: Sanitize interpolated values
console.msg.type()}]`, msg.text());
    }
  });
  page.on('pageerror', err => {
    console.log('[browser pageerror]', err.message);
  });
  page.on('requestfailed', req => {
    console.log('[network failed]', req.url(), req.failure()?.errorText);
  });
}
