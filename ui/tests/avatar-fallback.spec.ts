import { test, expect } from '@playwright/test';

test.describe('Avatar Fallback System', () => {
  test('should always provide audio even without API keys', async ({
    page,
  }) => {
    // Navigate to the portfolio page
    await page.goto('/');

    // Wait for the page to load and avatar panel to be visible
    await expect(page.locator('[data-dev="avatar-panel"]')).toBeVisible();

    // Click the "Play Introduction" button
    const playButton = page.locator('button:has-text("▶️ Play Introduction")');
    await expect(playButton).toBeVisible();
    await playButton.click();

    // Wait for audio element to appear (should happen within 10 seconds)
    const audioElement = page.locator('audio[controls]');
    await expect(audioElement).toBeVisible({ timeout: 10000 });

    // Verify audio element has a valid source
    const audioSrc = await audioElement.getAttribute('src');
    expect(audioSrc).toBeTruthy();
    expect(audioSrc).toMatch(/\/api\/assets\/(default-intro|.*\.mp3)/);

    // Verify the audio element can load (tests that the URL is accessible)
    const canPlay = await page.evaluate(() => {
      const audio = document.querySelector('audio') as HTMLAudioElement;
      return new Promise(resolve => {
        if (audio.readyState >= 2) {
          // Already loaded
          resolve(true);
          return;
        }

        const onCanPlay = () => {
          audio.removeEventListener('canplay', onCanPlay);
          audio.removeEventListener('error', onError);
          resolve(true);
        };

        const onError = () => {
          audio.removeEventListener('canplay', onCanPlay);
          audio.removeEventListener('error', onError);
          resolve(false);
        };

        audio.addEventListener('canplay', onCanPlay);
        audio.addEventListener('error', onError);

        // Trigger load if needed
        audio.load();

        // Timeout after 5 seconds
        setTimeout(() => {
          audio.removeEventListener('canplay', onCanPlay);
          audio.removeEventListener('error', onError);
          resolve(false);
        }, 5000);
      });
    });

    expect(canPlay).toBe(true);
  });

  test('should handle avatar photo upload gracefully', async ({ page }) => {
    // Navigate to portfolio page
    await page.goto('/');

    // Wait for avatar panel
    await expect(page.locator('[data-dev="avatar-panel"]')).toBeVisible();

    // Find file input
    const fileInput = page.locator('input[type="file"][name="photo"]');
    await expect(fileInput).toBeVisible();

    // Upload a test image (using a fixture)
    await fileInput.setInputFiles('./tests/fixtures/avatar.jpg');

    // Click upload button
    const uploadButton = page.locator('button:has-text("Upload Avatar")');
    await uploadButton.click();

    // Wait for either success or failure (should not hang indefinitely)
    await page.waitForFunction(
      () => {
        const button = document.querySelector(
          'button:has-text("Upload Avatar"), button:has-text("Uploading…")'
        );
        return !button?.textContent?.includes('Uploading…');
      },
      { timeout: 15000 }
    );

    // Verify upload completed (either success or graceful failure)
    const uploadButtonText = await uploadButton.textContent();
    expect(uploadButtonText).toBe('Upload Avatar'); // Should return to normal state

    // If upload succeeded, verify image preview appears
    const imgPreview = page.locator('img[alt="avatar"]');
    const hasPreview = (await imgPreview.count()) > 0;

    if (hasPreview) {
      await expect(imgPreview).toBeVisible();
      const imgSrc = await imgPreview.getAttribute('src');
      expect(imgSrc).toBeTruthy();
    }
  });

  test('should show model and namespace info', async ({ page }) => {
    // Navigate to portfolio page
    await page.goto('/');

    // Wait for chat panel to load
    await expect(page.locator('[data-dev="chat-panel"]')).toBeVisible();

    // Check for model info (should appear within 5 seconds)
    const modelInfo = page.locator('text=/Model:.*Namespace: portfolio/');
    await expect(modelInfo).toBeVisible({ timeout: 5000 });

    // Verify the text contains expected patterns
    const infoText = await modelInfo.textContent();
    expect(infoText).toMatch(/Model: .+ · Namespace: portfolio/);
    expect(infoText).not.toContain('loading');
  });

  test('should display quick prompt buttons', async ({ page }) => {
    // Navigate to portfolio page
    await page.goto('/');

    // Wait for chat box to be visible
    await expect(page.locator('[data-dev="chat-box"]')).toBeVisible();

    // Look for quick prompt buttons
    const quickPrompts = page
      .locator('button:has-text("Quick asks:")')
      .locator('..')
      .locator('button');
    const promptCount = await quickPrompts.count();

    // Should have at least a few quick prompt buttons
    expect(promptCount).toBeGreaterThan(0);

    if (promptCount > 0) {
      // Test clicking the first prompt button
      const firstPrompt = quickPrompts.first();
      const promptText = await firstPrompt.textContent();

      await firstPrompt.click();

      // Check that the input field was populated
      const chatInput = page.locator(
        'input[placeholder*="Ask"], textarea[placeholder*="Ask"]'
      );
      const inputValue = await chatInput.inputValue();

      // Input should contain some text (the prompt or a truncated version)
      expect(inputValue.length).toBeGreaterThan(0);
    }
  });
});

test.describe('API Integration', () => {
  test('should handle chat API gracefully', async ({ page }) => {
    // Navigate and wait for chat interface
    await page.goto('/');
    await expect(page.locator('[data-dev="chat-box"]')).toBeVisible();

    // Find chat input and submit button
    const chatInput = page.locator(
      'input[placeholder*="Ask"], textarea[placeholder*="Ask"]'
    );
    const submitButton = page.locator(
      'button:has-text("Send"), button[type="submit"]'
    );

    await expect(chatInput).toBeVisible();

    // Type a simple test message
    await chatInput.fill('What is your name?');
    await submitButton.click();

    // Wait for response (success or graceful failure)
    // Should show either a response or an error message, but not hang
    await page.waitForFunction(
      () => {
        const messages = document.querySelectorAll(
          '[data-dev="chat-message"], .message, .response'
        );
        return messages.length > 0;
      },
      { timeout: 20000 }
    );

    // Verify some kind of response appeared
    const responses = page.locator(
      '[data-dev="chat-message"], .message, .response'
    );
    const responseCount = await responses.count();
    expect(responseCount).toBeGreaterThan(0);

    // Check if it's an error or success response
    const responseText = await responses.last().textContent();
    expect(responseText).toBeTruthy();
    expect(responseText.length).toBeGreaterThan(0);
  });
});
