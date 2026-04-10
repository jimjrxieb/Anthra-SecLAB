import { test, expect } from '@playwright/test';

test('Chat endpoint responds via UI', async ({ page }) => {
  await page.goto('/');
  await page
    .getByPlaceholder('Ask about my AI/ML or DevSecOps work…')
    .fill('Tell me about the Jade project');
  await page.getByRole('button', { name: 'Ask' }).click();

  await expect(page.locator("[data-dev='chat-box']")).toBeVisible();
  await expect(page.getByText(/Jade|ZRS|RAG/i)).toBeVisible({ timeout: 20000 });
});
