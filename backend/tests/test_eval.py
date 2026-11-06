"""Step 4: the eval matcher and scorer behave as documented."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("evalrun", ROOT / "eval" / "run.py")
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)

GT = [
    {"id": "A", "file": "x/app.py", "line": 10, "cwe": "CWE-78", "kind": "direct"},
    {"id": "B", "file": "x/app.py", "line": 30, "cwe": "CWE-78", "kind": "wrapper"},
    {"id": "N", "file": "x/app.py", "line": 50, "cwe": "CWE-78", "kind": "negative-sanitized"},
]


def test_line_window_and_cwe():
    assert ev.matches(GT[0], ("x/app.py", 12, "CWE-78"))
    assert not ev.matches(GT[0], ("x/app.py", 13, "CWE-78"))
    assert not ev.matches(GT[0], ("x/app.py", 10, "CWE-89"))


def test_score_counts_negatives_and_precision():
    r = ev.score({("x/app.py", 10, "CWE-78"), ("x/app.py", 50, "CWE-78")}, GT)
    assert r["direct"]["caught"] == 1 and r["wrapper"]["caught"] == 0
    assert r["negatives_flagged"] == ["N"] and r["precision"] == 0.5


def test_cwe_normalisation():
    assert ev.norm_cwe("CWE-78: OS Command Injection") == "CWE-78"
    assert ev.norm_cwe("89") == "CWE-89"
    assert ev.norm_cwe("CWE-704", "python.flask.tainted-sql-string") == "CWE-89"
    assert ev.norm_cwe("CWE-327") is None


def test_ours_beats_baselines_on_wrappers():
    ours = ev.score(ev.run_ours(True), ev.json.loads((ROOT / "targets/ground_truth.json").read_text()))
    assert ours["wrapper"]["caught"] == 6 and ours["negatives_flagged"] == []
