"""LOG LEAK - VULNERABLE.

Rule: card numbers (PAN) must never be written to application logs.
Flaw: the full prompt, including whatever the customer typed, is logged.
Path: user_message -> prompt -> logger.info(prompt) -> log file.
OWASP LLM02:2025 Sensitive Information Disclosure. PCI DSS Req. 3.
"""
import logging

from cases.fakes import EchoLLM

log = logging.getLogger("support_bot")


def handle(user_message: str, llm: EchoLLM) -> str:
    prompt = f"You are a support bot.\nCustomer says: {user_message}"
    log.info("Sending prompt to LLM: %s", prompt)  # BUG: raw PAN in logs
    return llm.complete(prompt)
