import { test, expect } from '@playwright/test';

test('Chat answers and shows model banner', async ({ page }) => {
  await page.goto('/');

  // Verify landing page structure
  await expect(page.locator('[data-dev="landing"]')).toBeVisible();

  // Check for model info banner (from ChatPanel)
  await expect(page.getByText(/Model:/i)).toBeVisible({ timeout: 10000 });

  // Find chat input and try to interact
  const chatInput = page.getByPlaceholder(/Ask|Chat|Message/i);
  await expect(chatInput).toBeVisible();

  // Type a test message
  await chatInput.fill('Tell me about the Jade project');

  // Find and click send/ask button
  const sendButton = page.getByRole('button', { name: /Ask|Send|Submit/i });
  await sendButton.click();

  // Wait for response (should contain relevant keywords)
  await expect(page.getByText(/ZRS|Jade|RAG|property|management/i)).toBeVisible(
    { timeout: 20000 }
  );
});

test('UI shows only core components', async ({ page }) => {
  await page.goto('/');

  // Verify main landing structure
  await expect(page.locator('[data-dev="landing"]')).toBeVisible();

  // Verify all three core components are present
  await expect(page.locator('[data-dev="avatar-panel"]')).toBeVisible();
  await expect(page.locator('[data-dev="chat-panel"]')).toBeVisible();
  await expect(page.locator('[data-dev="projects"]')).toBeVisible();

  // Verify no legacy components are rendered
  await expect(page.locator('[data-dev="interview-panel"]')).not.toBeVisible();
  await expect(page.locator('[data-dev="jade-black-home"]')).not.toBeVisible();
  await expect(page.locator('[data-dev="modern-home"]')).not.toBeVisible();
});

test('Content sources work correctly', async ({ page }) => {
  await page.goto('/');

  // Check projects from JSON file
  await expect(page.getByText('Jade @ ZRS Management')).toBeVisible();
  await expect(page.getByText('LinkOps Afterlife')).toBeVisible();

  // Check for GitHub/demo links
  await expect(page.getByRole('link', { name: 'GitHub' })).toBeVisible();
  await expect(
    page.getByRole('link', { name: /Live Demo|Create Your Avatar/i })
  ).toBeVisible();

  // Check for quick Q&A buttons (from qa.json)
  await expect(page.getByText(/Quick asks|What AI\/ML work/i)).toBeVisible();
});

test('Avatar panel functionality', async ({ page }) => {
  await page.goto('/');

  const avatarPanel = page.locator('[data-dev="avatar-panel"]');
  await expect(avatarPanel).toBeVisible();

  // Check for file upload
  await expect(avatarPanel.locator('input[type="file"]')).toBeVisible();

  // Check for Play Introduction button
  const playButton = avatarPanel.getByRole('button', {
    name: /Play Introduction/i,
  });
  await expect(playButton).toBeVisible();

  // Click play button and expect audio element to appear
  await playButton.click();
  await expect(page.locator('audio[controls]')).toBeVisible({ timeout: 10000 });
});
