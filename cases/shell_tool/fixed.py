"""SHELL TOOL - FIXED.

Fix: the model picks a diagnostic by NAME from an allowlist. The server maps
the name to a fixed argument list and runs it without a shell. The model's
text never becomes part of a command.
"""
import subprocess

from cases.fakes import ScriptedLLM

ALLOWED = {
    "health": ["echo", "health ok"],
    "python_version": ["python3", "--version"],
}


def run_agent(task: str, llm: ScriptedLLM) -> list[str]:
    def run_diagnostic(name: str) -> str:
        argv = ALLOWED.get(name)
        if argv is None:
            return f"unknown diagnostic {name!r}"
        done = subprocess.run(argv, capture_output=True, text=True)
        return done.stdout

    results = []
    while (call := llm.next_tool_call(task)) is not None:
        results.append(run_diagnostic(**call["args"]))
    return results
