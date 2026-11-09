"""SHELL TOOL - VULNERABLE.

Rule: the IT-helpdesk agent may only run a fixed set of diagnostic commands.
Flaw: the model writes a command string and it is run through a shell.
A user (or injected content) can append "; anything" and it runs too.
OWASP LLM06:2025 Excessive Agency + LLM05 Improper Output Handling. CWE-78.
"""
import subprocess

from cases.fakes import ScriptedLLM


def run_agent(task: str, llm: ScriptedLLM) -> list[str]:
    def run_diagnostic(command: str) -> str:
        done = subprocess.run(command, shell=True, capture_output=True, text=True)  # BUG
        return done.stdout

    results = []
    while (call := llm.next_tool_call(task)) is not None:
        results.append(run_diagnostic(**call["args"]))
    return results
