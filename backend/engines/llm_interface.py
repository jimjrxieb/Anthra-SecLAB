import os
import logging
from typing import AsyncGenerator

logger = logging.getLogger(__name__)


class LLMEngine:
    """
    Unified LLM Engine supporting multiple providers:
    - Claude (Anthropic) - Primary and recommended
    - Local (HuggingFace Transformers) - Optional fallback
    """

    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "claude")  # claude or local
        self.model_name = os.getenv("LLM_MODEL")

        if self.provider == "local":
            if not self.model_name:
                self.model_name = "Qwen/Qwen2.5-1.5B-Instruct"
            self._load_local_model()
        elif self.provider == "claude":
            self.claude_api_key = os.getenv("CLAUDE_API_KEY")
            self.claude_model = self.model_name or "claude-3-haiku-20240307"
            if not self.claude_api_key:
                logger.error("CLAUDE_API_KEY not set! Claude provider will fail.")
                raise ValueError("CLAUDE_API_KEY environment variable is required for Claude provider")
            logger.info(f"Using Claude provider with model: {self.claude_model}")
        else:
            raise ValueError(f"Unknown LLM provider: {self.provider}. Use 'claude' or 'local'")

    def _load_local_model(self):
        """Load local transformers model (lazy import dependencies)"""
        try:
            # Only import transformers and torch when actually using local models
            from transformers import AutoTokenizer, AutoModelForCausalLM
            import torch

            logger.info(f"Loading local model: {self.model_name}")
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                revision="c6e32e2e8e1b2c7d3a4b5c6d7e8f9a0b1c2d3e4f"
            )
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                revision="c6e32e2e8e1b2c7d3a4b5c6d7e8f9a0b1c2d3e4f",
                torch_dtype=(
                    torch.float16 if torch.cuda.is_available() else torch.float32
                ),
                device_map="auto" if torch.cuda.is_available() else None,
                trust_remote_code=True,
            )
            logger.info(f"Local model loaded successfully: {self.model_name}")
        except Exception as e:
            logger.error(f"Failed to load local model {self.model_name}: {e}")
            raise

    async def generate(
        self, prompt: str, max_tokens: int = 1024
    ) -> AsyncGenerator[str, None]:
        """Generate streaming response from configured LLM provider"""
        if self.provider == "claude":
            async for chunk in self._generate_claude(prompt, max_tokens):
                yield chunk
        elif self.provider == "local":
            async for chunk in self._generate_local(prompt, max_tokens):
                yield chunk
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    async def _generate_claude(self, prompt: str, max_tokens: int) -> AsyncGenerator[str, None]:
        """Generate using Claude (Anthropic) API with streaming"""
        try:
            from anthropic import AsyncAnthropic

            client = AsyncAnthropic(api_key=self.claude_api_key)

            logger.info(f"Calling Claude API with model: {self.claude_model}")

            async with client.messages.stream(
                model=self.claude_model,
                max_tokens=max_tokens,
                temperature=0.7,
                messages=[{"role": "user", "content": prompt}],
            ) as stream:
                async for text in stream.text_stream:
                    yield text

        except Exception as e:
            logger.error(f"Claude API error: {e}", exc_info=True)
            yield f"Error: Unable to generate response. {str(e)}"

    async def _generate_local(
        self, prompt: str, max_tokens: int
    ) -> AsyncGenerator[str, None]:
        """Generate using local HuggingFace model with streaming"""
        try:
            # Lazy import for local model dependencies
            from transformers import TextIteratorStreamer
            import torch
            import threading

            logger.info(f"Generating with local model: {self.model_name}")

            inputs = self.tokenizer.encode(prompt, return_tensors="pt")
            if torch.cuda.is_available():
                inputs = inputs.to("cuda")

            streamer = TextIteratorStreamer(self.tokenizer, skip_special_tokens=True)

            generation_kwargs = dict(
                input_ids=inputs,
                max_length=len(inputs[0]) + max_tokens,
                streamer=streamer,
                do_sample=True,
                temperature=0.7,
                pad_token_id=self.tokenizer.eos_token_id,
            )

            thread = threading.Thread(
                target=self.model.generate, kwargs=generation_kwargs
            )
            thread.start()

            generated_text = ""
            for new_text in streamer:
                if prompt not in new_text:
                    generated_text += new_text
                    yield new_text

        except Exception as e:
            logger.error(f"Local generation error: {e}", exc_info=True)
            yield f"Error: Unable to generate response. {str(e)}"

    async def chat_completion(self, messages: list, max_tokens: int = 1024, temperature: float = 0.4) -> dict:
        """
        Non-streaming chat completion (for simple request/response)
        messages: list of {"role": "system"|"user"|"assistant", "content": str}
        temperature: lower values (0.1-0.4) for factual RAG responses, higher (0.7+) for creative
        Returns: {"content": str, "model": str}
        """
        try:
            if self.provider == "claude":
                return await self._chat_completion_claude(messages, max_tokens, temperature)
            elif self.provider == "local":
                return await self._chat_completion_local(messages, max_tokens, temperature)
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
        except Exception as e:
            logger.error(f"Chat completion error: {e}", exc_info=True)
            return {
                "content": f"I'm having trouble generating a response right now. Error: {str(e)}",
                "model": f"{self.provider}/error",
            }

    async def _chat_completion_claude(self, messages: list, max_tokens: int, temperature: float = 0.4) -> dict:
        """Chat completion using Claude (Anthropic) API"""
        try:
            from anthropic import AsyncAnthropic

            client = AsyncAnthropic(api_key=self.claude_api_key)

            # Extract system message if present
            system_message = None
            api_messages = []
            for msg in messages:
                if msg["role"] == "system":
                    system_message = msg["content"]
                else:
                    api_messages.append(msg)

            logger.info(f"Calling Claude API with model: {self.claude_model}, temp: {temperature}")

            response = await client.messages.create(
                model=self.claude_model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system_message if system_message else None,
                messages=api_messages,
            )

            return {
                "content": response.content[0].text,
                "model": self.claude_model,
            }

        except Exception as e:
            logger.error(f"Claude API error: {e}", exc_info=True)
            raise

    async def _chat_completion_local(self, messages: list, max_tokens: int, temperature: float = 0.4) -> dict:
        """Chat completion using local HuggingFace model"""
        try:
            import torch

            # Combine messages into a prompt
            prompt = "\n".join([f"{msg['role']}: {msg['content']}" for msg in messages])
            prompt += "\nassistant:"

            logger.info(f"Generating with local model: {self.model_name}, temp: {temperature}")

            inputs = self.tokenizer.encode(prompt, return_tensors="pt")
            if torch.cuda.is_available():
                inputs = inputs.to("cuda")

            outputs = self.model.generate(
                input_ids=inputs,
                max_length=len(inputs[0]) + max_tokens,
                do_sample=True,
                temperature=temperature,
                pad_token_id=self.tokenizer.eos_token_id,
            )

            response_text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            # Remove the prompt from response
            response_text = response_text[len(prompt):].strip()

            return {
                "content": response_text,
                "model": self.model_name,
            }

        except Exception as e:
            logger.error(f"Local generation error: {e}", exc_info=True)
            raise


# Global instance
_llm_engine = None


def get_llm_engine() -> LLMEngine:
    """Get or create global LLM engine instance"""
    global _llm_engine
    if _llm_engine is None:
        _llm_engine = LLMEngine()
    return _llm_engine
