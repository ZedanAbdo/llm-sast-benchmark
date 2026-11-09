"""SHELL TOOL - NEAR-MISS (looks vulnerable, is safe).

The model's text DOES reach subprocess.run, which looks like command injection.
It is safe because:
  - no shell is used (argument list, not a string), so ; | && have no meaning
  - the value must match a strict hostname pattern before it is used
  - it is passed after "--", so it can't be read as a command-line option
"""
import re
import subprocess

from cases.fakes import ScriptedLLM

HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9-]+)*$")


def run_agent(task: str, llm: ScriptedLLM) -> list[str]:
    def check_host(host: str) -> str:
        if not HOSTNAME.fullmatch(host):
            return f"invalid hostname {host!r}"
        done = subprocess.run(["echo", "checking", "--", host], capture_output=True, text=True)
        return done.stdout

    results = []
    while (call := llm.next_tool_call(task)) is not None:
        results.append(check_host(**call["args"]))
    return results
