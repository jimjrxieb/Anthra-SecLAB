export const API_BASE =
  import.meta.env.VITE_API_BASE_URL || '/api';

export type ChatRequest = {
  message: string;
  namespace?: string;
  k?: number;
  filters?: Record<string, unknown>;
};

export type Citation = {
  text: string;
  score: number;
  metadata?: Record<string, unknown>;
};
export type ChatResponse = {
  answer: string;
  citations: Citation[];
  model: string;
};

export async function chat(
  req: ChatRequest,
  signal?: AbortSignal
): Promise<ChatResponse> {
  // Map to our backend API format
  const backendRequest = {
    message: req.message,
    audience_type: 'general',
    context: null,
  };

  const r = await fetch(`${API_BASE}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(backendRequest),
    signal,
  });

  if (!r.ok) {
    const detail = await safeJson(r);
    throw new Error(`Chat failed (${r.status}): ${JSON.stringify(detail)}`);
  }

  const response = await r.json();

  // Map backend response to frontend format
  return {
    answer:
      response.answer ||
      response.response ||
      response.text_response ||
      "I'm having trouble responding right now.",
    citations: [],
    model: 'sheyla-avatar',
  };
}

async function safeJson(r: Response) {
  try {
    return await r.json();
  } catch {
    return await r.text();
  }
}
