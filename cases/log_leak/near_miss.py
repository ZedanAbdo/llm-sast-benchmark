"""LOG LEAK - NEAR-MISS (looks vulnerable, is safe).

The prompt variable flows into the logger call, which looks like the same bug.
But only the prompt's LENGTH and a one-way hash are logged, never its content.
Useful for debugging ("was the same prompt sent twice?") without exposing data.
"""
import hashlib
import logging

from cases.fakes import EchoLLM

log = logging.getLogger("support_bot")


def handle(user_message: str, llm: EchoLLM) -> str:
    prompt = f"You are a support bot.\nCustomer says: {user_message}"
    digest = hashlib.sha256(prompt.encode()).hexdigest()[:12]
    log.info("Sending prompt to LLM: %d chars, sha256=%s", len(prompt), digest)
    return llm.complete(prompt)
