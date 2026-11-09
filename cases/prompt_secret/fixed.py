"""PROMPT SECRET - FIXED.

Fix: the model never sees the key. The key lives in an environment variable
and is used only inside server-side code (the billing tool). If the system
prompt leaks, there is nothing secret in it.
"""
import os

from cases.fakes import ObedientLLM

SYSTEM_PROMPT = (
    "You are a billing assistant. To check invoices, call the check_invoice tool."
)


def check_invoice(invoice_id: str) -> str:
    key = os.environ.get("BILLING_API_KEY", "")
    # A real version would call the billing API with `key` here.
    return f"invoice {invoice_id}: paid" if key else "billing unavailable"


def chat(user_message: str, llm: ObedientLLM) -> str:
    return llm.chat(SYSTEM_PROMPT, user_message)
