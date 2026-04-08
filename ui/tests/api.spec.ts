import { test, expect } from '@playwright/test';
import fs from 'node:fs';

const apiBase = process.env.API_URL || 'http://localhost:8001';

test('API health', async ({ request }) => {
  const r = await request.get(`${apiBase}/health`);
  expect(r.ok()).toBeTruthy();
  const body = await r.json();
  expect(body.ok).toBeTruthy();
});

test('Chat endpoint responds', async ({ request }) => {
  const r = await request.post(`${apiBase}/api/chat`, {
    data: { message: 'Briefly describe Jade at ZRS.' },
  });
  expect(r.ok()).toBeTruthy();
  const body = await r.json();
  expect(body.answer && body.answer.length > 5).toBeTruthy();
});

test('Upload image → avatar talk (skips if keys not present)', async ({
  request,
}, testInfo) => {
  // Skip if envs not set
  if (!process.env.DID_API_KEY || !process.env.ELEVENLABS_API_KEY) {
    test.skip(
      true,
      'D-ID/ElevenLabs keys not set in env → skipping avatar test'
    );
  }

  const fixture = testInfo.project.name.includes('chromium')
    ? 'tests/fixtures/avatar.jpg'
    : 'tests/fixtures/avatar.jpg';
  expect(fs.existsSync(fixture)).toBeTruthy();

  // Upload
  const up = await request.post(`${apiBase}/api/upload/image`, {
    multipart: { file: fs.createReadStream(fixture) as any },
  });
  expect(up.ok()).toBeTruthy();
  const { url } = await up.json();
  expect(url).toContain('/uploads/images/');

  // Create talk
  const talk = await request.post(`${apiBase}/api/avatar/talk`, {
    data: { text: 'Hello from Jade.', image_url: url },
  });
  expect(talk.ok()).toBeTruthy();
  const t = await talk.json();
  expect(t.talk_id).toBeTruthy();

  // Poll for result_url (up to ~45s)
  let resultUrl: string | null = null;
  for (let i = 0; i < 30; i++) {
    const s = await request.get(`${apiBase}/api/avatar/talk/${t.talk_id}`);
    expect(s.ok()).toBeTruthy();
    const body = await s.json();
    if (body.result_url) {
      resultUrl = body.result_url;
      break;
    }
    await new Promise(res => setTimeout(res, 1500));
  }
  expect(resultUrl, 'D-ID never returned a result_url').toBeTruthy();
});
