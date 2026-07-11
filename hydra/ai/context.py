"""Context management — tracks token usage and compacts history."""

from __future__ import annotations


class ContextManager:
    """Manages context window: what fits, what gets compacted."""

    CHARS_PER_TOKEN = 4  # rough estimate

    def estimate_tokens(self, messages: list[dict]) -> int:
        total_chars = sum(len(m.get("content", "")) for m in messages)
        return total_chars // self.CHARS_PER_TOKEN

    def fits(self, messages: list[dict], max_tokens: int) -> bool:
        return self.estimate_tokens(messages) <= max_tokens

    def compact(self, messages: list[dict], target_tokens: int) -> list[dict]:
        """Drop older messages to fit within target_tokens, keeping system + recent."""
        if self.fits(messages, target_tokens):
            return messages

        system = [m for m in messages if m.get("role") == "system"]
        non_system = [m for m in messages if m.get("role") != "system"]

        result = list(system)
        for msg in reversed(non_system):
            candidate = result + [msg]
            if self.estimate_tokens(candidate) > target_tokens:
                break
            result.append(msg)

        non_sys_result = [m for m in result if m.get("role") != "system"]
        non_sys_result.reverse()
        return system + non_sys_result

    def inject_context(self, messages: list[dict], context: str) -> list[dict]:
        """Prepend a system context message."""
        return [{"role": "system", "content": context}] + messages
