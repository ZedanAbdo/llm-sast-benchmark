# LLM SAST Benchmark

A small, reproducible benchmark that measures how well static analysis tools
find security vulnerabilities in LLM applications.

**New to the project? Start with [WALKTHROUGH.md](WALKTHROUGH.md),** a
step-by-step explanation of every part.

## Results

| Tool | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| Semgrep (custom LLM rules) | 4 | 4 | 0 | 4 | 50% | 100% | 0.67 |
| Bandit (all severities) | 1 | 2 | 3 | 6 | 33% | 25% | 0.29 |
| Bandit (MEDIUM and above) | 1 | 0 | 3 | 8 | 100% | 25% | 0.40 |

Per-file detail: [SCORECARD.md](SCORECARD.md).

**Key finding:** static tools see code *shape*, not security *meaning*. Bandit
missed every LLM-specific flaw. Custom Semgrep rules found them all, but also
flagged 4 of 8 safe files, because they can't see allowlists, server-side
mappings, or the fact that a hash no longer contains the secret.

## Cases

Each case has `vulnerable.py`, `fixed.py`, and `near_miss.py` (safe code that looks vulnerable).

| Case | Risk | OWASP LLM 2025 |
|---|---|---|
| `log_leak` | Card numbers written to logs via the prompt | LLM02 |
| `prompt_secret` | API key placed in the system prompt | LLM07, LLM02 |
| `indirect_injection` | Hidden text in a web page makes the agent email customer data out | LLM01 → LLM06, LLM02 |
| `shell_tool` | Model-written command run with `shell=True` | LLM06, LLM05 (CWE-78) |

## Run it

```bash
pip install pytest semgrep bandit pyyaml
python -m pytest -v      # 19 tests proving each file's label
python bench.py          # runs the tools and regenerates SCORECARD.md
```

No API keys or network needed. Fake LLMs (`cases/fakes.py`) make every run deterministic.

## Method

1. Write the security rule for each case first.
2. Prove each file's label with an exploit test (`tests/`).
3. Record labels in `manifest.yaml` (the answer key).
4. Run each tool, compare to the answer key, and compute precision, recall and F1.

Semgrep rules were written as general heuristics and **not tuned to the test
files**, to avoid overfitting the benchmark.

## Limitations

- 12 files is a small sample; the numbers show patterns, not statistically strong conclusions.
- The case author also wrote the Semgrep rules. Independent rule authors would give a fairer test.
- File-level scoring: a finding on the wrong line of a vulnerable file still counts as a TP.
