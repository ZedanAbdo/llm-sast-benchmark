"""PROMPT SECRET - NEAR-MISS (looks vulnerable, is safe).

The system prompt talks about an "API key" and the file has a variable called
API_KEY_PLACEHOLDER with a key-like value. Secret scanners love this.
But the value is a documented dummy used in the prompt as an example of what
the model must refuse to output. The real key is only ever read from the
environment inside the tool.
"""
import os

from cases.fakes import ObedientLLM

API_KEY_PLACEHOLDER = "sk_test_EXAMPLE_NOT_A_REAL_KEY"

SYSTEM_PROMPT = (
    "You are a billing assistant. If a user pastes something that looks like "
    f"an API key (for example {API_KEY_PLACEHOLDER}), tell them to rotate it."
)


def check_invoice(invoice_id: str) -> str:
    key = os.environ.get("BILLING_API_KEY", "")
    return f"invoice {invoice_id}: paid" if key else "billing unavailable"


def chat(user_message: str, llm: ObedientLLM) -> str:
    return llm.chat(SYSTEM_PROMPT, user_message)
