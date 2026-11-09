"""LOG LEAK - FIXED.

Fix: mask anything that looks like a card number (13-19 digits, with optional
spaces or dashes) BEFORE it is logged. Keep the last 4 digits for support use.
"""
import logging
import re

from cases.fakes import EchoLLM

log = logging.getLogger("support_bot")
PAN_PATTERN = re.compile(r"\b(?:\d[ -]?){9,15}(\d{4})\b")


def redact(text: str) -> str:
    return PAN_PATTERN.sub(r"[PAN ****\1]", text)


def handle(user_message: str, llm: EchoLLM) -> str:
    prompt = f"You are a support bot.\nCustomer says: {user_message}"
    log.info("Sending prompt to LLM: %s", redact(prompt))
    return llm.complete(prompt)
