/**
 * Fixed ChatBox Component
 * Simple, working chat interface for Sheyla
 */

import React, { useState, useRef, useEffect } from 'react';
import { API_BASE } from '../lib/api';

interface ChatMessage {
  id: string;
  text: string;
  sender: 'user' | 'sheyla';
  timestamp: Date;
}

const ChatBoxFixed: React.FC = () => {
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when messages change (scroll container only, not page)
  useEffect(() => {
    if (messagesContainerRef.current) {
      messagesContainerRef.current.scrollTop = messagesContainerRef.current.scrollHeight;
    }
  }, [messages, loading]);

  const quickPrompts = [
    "How does Jimmie approach securing a Kubernetes cluster?",
    'How did Jimmie secure this application?',
    'What technologies does Jimmie use?',
    'How was the CI/CD pipeline built?',
    'What security tools were implemented?',
  ];

  const sendMessage = async (text: string) => {
    if (!text.trim()) return;

    const userMessage: ChatMessage = {
      id: Date.now() + '-user',
      text: text.trim(),
      sender: 'user',
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMessage]);
    setMessage('');
    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE}/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: text.trim(),
          audience_type: 'general',
        }),
      });

      if (!response.ok) {
        const errorData = await response
          .json()
          .catch(() => ({ detail: 'Unknown error' }));
        throw new Error(errorData.detail || `HTTP ${response.status}`);
      }

      const data = await response.json();

      const sheylaMessage: ChatMessage = {
        id: Date.now() + '-sheyla',
        text: data.answer || data.response || "I'm having trouble responding right now.",
        sender: 'sheyla',
        timestamp: new Date(),
      };

      setMessages(prev => [...prev, sheylaMessage]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');

      // Add error message to chat
      const errorMessage: ChatMessage = {
        id: Date.now() + '-error',
        text: `Sorry—something went wrong reaching my brain.\n${err instanceof Error ? err.message : 'Unknown error'}`,
        sender: 'sheyla',
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    sendMessage(message);
  };

  const handleQuickPrompt = (prompt: string) => {
    sendMessage(prompt);
  };

  return (
    <div className="space-y-4">
      {/* Chat Header */}
      <div className="flex items-center gap-3 pb-3 border-b border-white/10">
        <div className="w-10 h-10 rounded-full bg-gradient-to-br from-crystal-400 to-jade-500 flex items-center justify-center">
          <span className="text-white font-bold text-sm">S</span>
        </div>
        <div>
          <h3 className="text-white font-semibold text-sm">Sheyla</h3>
          <p className="text-crystal-400 text-xs">AI Portfolio Assistant</p>
        </div>
        <div className="ml-auto">
          <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-xs ${
            loading
              ? 'bg-gold-500/20 text-gold-400'
              : 'bg-jade-500/20 text-jade-400'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${loading ? 'bg-gold-400 animate-pulse' : 'bg-jade-400'}`}></span>
            {loading ? 'Thinking...' : 'Online'}
          </span>
        </div>
      </div>

      {/* Chat Messages */}
      <div ref={messagesContainerRef} className="space-y-3 max-h-80 overflow-y-auto pr-2">
        {messages.length === 0 && (
          <div className="text-center py-8">
            <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-gradient-to-br from-crystal-500/20 to-jade-500/20 flex items-center justify-center">
              <span className="text-2xl">👋</span>
            </div>
            <p className="text-white font-medium">Hi! I'm Sheyla</p>
            <p className="text-text-secondary text-sm mt-1">
              Ask me about Jimmie's approach to securing and optimizing infrastructure
            </p>
          </div>
        )}

        {messages.map(msg => (
          <div
            key={msg.id}
            className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={`max-w-[85%] px-4 py-3 rounded-2xl ${
                msg.sender === 'user'
                  ? 'bg-crystal-600 text-white rounded-br-md'
                  : 'bg-snow/10 text-white border border-white/5 rounded-bl-md'
              }`}
            >
              <p className="text-sm whitespace-pre-wrap leading-relaxed">{msg.text}</p>
              <p className={`text-xs mt-2 ${msg.sender === 'user' ? 'text-crystal-200' : 'text-text-secondary'}`}>
                {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </p>
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex justify-start">
            <div className="bg-snow/10 border border-white/5 px-4 py-3 rounded-2xl rounded-bl-md">
              <div className="flex items-center gap-2">
                <div className="flex gap-1">
                  <span className="w-2 h-2 bg-crystal-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></span>
                  <span className="w-2 h-2 bg-crystal-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></span>
                  <span className="w-2 h-2 bg-crystal-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></span>
                </div>
                <span className="text-text-secondary text-sm ml-1">Sheyla is typing...</span>
              </div>
            </div>
          </div>
        )}
        {/* Auto-scroll target */}
        <div ref={messagesEndRef} />
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-lg">
          <p className="text-sm flex items-center gap-2">
            <span>⚠️</span>
            <span>{error}</span>
          </p>
        </div>
      )}

      {/* Quick Prompts */}
      <div className="space-y-2">
        <p className="text-xs text-text-secondary">Quick asks:</p>
        <div className="flex flex-wrap gap-2">
          {quickPrompts.slice(0, 3).map((prompt, index) => (
            <button
              key={index}
              onClick={() => handleQuickPrompt(prompt)}
              disabled={loading}
              className="text-xs bg-snow/5 hover:bg-snow/10 text-crystal-400 hover:text-crystal-300 px-3 py-1.5 rounded-full border border-white/10 hover:border-crystal-500/30 transition-all disabled:opacity-50"
            >
              {prompt.length > 25 ? prompt.substring(0, 25) + '...' : prompt}
            </button>
          ))}
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="space-y-2">
        <div className="flex gap-2">
          <input
            type="text"
            value={message}
            onChange={e => setMessage(e.target.value)}
            placeholder="Ask about securing or optimizing infrastructure..."
            disabled={loading}
            className="flex-1 px-4 py-2.5 bg-snow/5 border border-white/10 rounded-xl text-white placeholder-text-secondary/50 focus:outline-none focus:ring-2 focus:ring-crystal-500/50 focus:border-crystal-500/50 disabled:opacity-50 text-sm"
          />
          <button
            type="submit"
            disabled={loading || !message.trim()}
            className="px-5 py-2.5 bg-gradient-to-r from-crystal-600 to-crystal-500 text-white rounded-xl hover:from-crystal-500 hover:to-crystal-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all font-medium text-sm shadow-lg shadow-crystal-500/20"
          >
            Ask
          </button>
        </div>
      </form>
    </div>
  );
};

export default ChatBoxFixed;
