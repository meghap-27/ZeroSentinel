# Status

Current step: **8, L3 early detection** (next)
Hackathon clock start: _set at kickoff_

| # | Step | State | Gate evidence | Commit | Notes / deviations |
|---|---|---|---|---|---|
| 0 | Setup | done | `pytest -q`: 3 passed; schema imports | step-0 | Python 3.13 in build env (PRD says 3.11; compatible) |
| 1 | Targets | done | `pytest -q`: 8 passed; 12 positives (6 direct, 6 wrapper), 6 negatives (3 sanitized, 3 dead code) | step-1 | Sinks added beyond PRD list: os.popen, send_file, shutil.copy, os.remove, executescript (see D9) |
| 2 | L2 taint | done | `pytest -q`: 34 passed. Direct 6/6 found; sanitized negatives 0/3 flagged | step-2+3 | Built with step 3: one engine (callgraph.py, taint.py, scanner.py). Sanitizers are per-CWE (shlex.quote does not clear path traversal). realpath+startswith guard not yet modelled |
| 3 | L2 wrappers | done | Wrapper 6/6 found with route-to-sink path; dead-code 3/3 reported only as `taint-unreachable` / pattern-match; 0 unexpected reachable findings | step-2+3 | Path length capped at 8 hops. Methods on classes not resolved (top-level functions only) |
| 4 | Eval harness | done | Ours 6/6 direct, 6/6 wrapper, 0/6 safe flagged; Bandit 4/6, 3/6, 3/6; Semgrep 5/6, 2/6, 3/6 (eval/results.md) | step-4,5,6 | Semgrep registry blocked in build env: ran 127 open-source semgrep-rules (python/lang + flask security). Same team wrote targets and scanner |
| 5 | L5 severity + API | done | `pytest`: 51 passed; zip scan end to end via API | step-4,5,6 | Endpoints under /api; findings PATCH is scan-scoped: /api/scans/{id}/findings/{fid}. No SARIF/PDF yet (step 11) |
| 6 | L1 ingestion | done | zip-slip, size cap, filter and snippet tests pass | step-4,5,6 | GitHub URL clone not built yet |
| 7 | Frontend | done | Upload → findings → trace detail → status change persists; filmed in demo video | step-7 | No charts (fallback); served by FastAPI from frontend/dist |
| 8 | L3 early detection | todo | | | |
| 9 | L4 proof + patch | todo | | | human review of app/verify/ required |
| 10 | ML ranker | todo | | | |
| 11 | Polish | todo | | | freeze at hour 20 |
| 12 | Stretch: fix-watcher | todo | | | only if ahead |

## Early finding: Bandit baseline (preview before step 4)
Bandit flags command-injection sinks by pattern (`os.system`, `shell=True`) wherever they appear, including inside helpers. On the seeded targets it hits CMD-W1, CMD-W2 and SQL-W2 by line, but it also flags all three sanitized/dead-code negatives in the cmd and sqli apps, and it finds nothing for path traversal.
**Implication:** the claim must be "more wrapper bugs found, with a source-to-sink path, at higher precision", not "every wrapper bug Bandit misses". Step 4 measures this properly.

## Known limitations (for the slide)
- Python and Flask only; decorator routes only; dynamic dispatch is not resolved.
- Three bug classes: CWE-78, CWE-89, CWE-22.
- Small evaluation sample; numbers are indicative.
- Only top-level functions are followed; class methods, decorators other than routes and dynamic `getattr` calls are not resolved (they are listed as unresolved).
- `realpath` + `startswith` prefix guards are not yet recognised as sanitizers.
- Fix-watcher output is leads, not proof.
