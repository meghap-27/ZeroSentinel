# Eval: seeded targets

Sample: 12 seeded bugs (6 direct, 6 through helpers) and 6 safe cases across 3 small Flask apps. **n is small; treat the numbers as indicative.**

Semgrep rules: open-source semgrep-rules python/lang/security + python/flask/security (127 rules, commit 16b9e6d; registry p/python unreachable from build env). Match: same file and CWE, line within ±2.

Caveat: the targets and the scanner were written by the same team, so this checks the approach, not real-world recall.

| Tool | Direct bugs | Helper (wrapper) bugs | Safe cases wrongly flagged | Precision |
|---|---|---|---|---|
| Bandit | 4/6 | 3/6 | 3/6 | 0.54 |
| Semgrep | 5/6 | 2/6 | 3/6 | 0.70 |
| ZeroSentinel (reachable findings) | 6/6 | 6/6 | 0/6 | 1.00 |
| ZeroSentinel (all, incl. low-confidence) | 6/6 | 6/6 | 3/6 | 0.80 |
