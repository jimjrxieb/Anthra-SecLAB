import React, { useEffect, useState } from 'react';
import ChatBoxFixed from './ChatBoxFixed';
import { API_BASE } from '../lib/api';

export default function ChatPanel() {
  const [health, setHealth] = useState<{
    llm_model?: string;
    llm_provider?: string;
    rag_namespace?: string;
    status?: string;
  }>({});

  useEffect(() => {
    fetch(`${API_BASE}/health`)
      .then(r => r.json())
      .then(data => {
        // Map backend health response to expected format
        setHealth({
          llm_model: data.model || 'gpt-4o-mini',
          llm_provider: 'openai',
          rag_namespace: 'portfolio',
          status: data.status,
        });
      })
      .catch(console.error);
  }, []);

  return (
    <div className="space-y-2">
      {/* Debug info hidden in production */}
      <ChatBoxFixed />
    </div>
  );
}
