"""Step 4: compare ZeroSentinel with Bandit and Semgrep on the seeded targets.

Matching rule: same file, same CWE, sink line within +/-2. Only the three in-scope
CWEs count; anything else a tool reports is ignored. Writes eval/results.json and
eval/results.md. Usage: python eval/run.py [--semgrep-config PATH_OR_REGISTRY]
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "targets"
sys.path.insert(0, str(ROOT / "backend"))
from app.detect.scanner import scan_project  # noqa: E402

SCOPE = {"CWE-78", "CWE-89", "CWE-22"}
APPS = ("cmd_app", "sqli_app", "path_app")


def norm_cwe(raw: str, rule: str = "") -> str | None:
    if "sql" in rule.lower():
        return "CWE-89"  # Semgrep tags tainted-sql-string as CWE-704; count it as SQLi
    for c in SCOPE:
        if raw.startswith(c + ":") or raw == c or raw == c.split("-")[1]:
            return c
    return None


def run_bandit() -> set[tuple]:
    out = subprocess.run(["bandit", "-r", str(TARGETS), "-f", "json", "-q"],
                         capture_output=True, text=True).stdout
    hits = set()
    for r in json.loads(out)["results"]:
        cwe = norm_cwe(str(r.get("issue_cwe", {}).get("id", "")))
        if cwe:
            hits.add((Path(r["filename"]).relative_to(TARGETS).as_posix(), r["line_number"], cwe))
    return hits


def run_semgrep(config: str) -> set[tuple]:
    out = subprocess.run(["semgrep", "--config", config, "--json", "--quiet", "--metrics=off",
                          str(TARGETS)], capture_output=True, text=True, timeout=600).stdout
    hits = set()
    for r in json.loads(out)["results"]:
        for raw in r["extra"]["metadata"].get("cwe", []) or [""]:
            cwe = norm_cwe(raw, r["check_id"])
            if cwe:
                rel = Path(r["path"]).resolve().relative_to(TARGETS).as_posix()
                hits.add((rel, r["start"]["line"], cwe))
    return hits


def run_ours(reachable_only: bool) -> set[tuple]:
    hits = set()
    for app in APPS:
        for f in scan_project(TARGETS / app, app):
            if reachable_only and f.confidence_tier == "pattern-match":
                continue
            hits.add((f"{app}/{f.file}", f.line, f.cwe))
    return hits


def matches(row: dict, hit: tuple) -> bool:
    return hit[0] == row["file"] and hit[2] == row["cwe"] and abs(hit[1] - row["line"]) <= 2


def score(hits: set[tuple], gt: list[dict]) -> dict:
    res = {}
    for kind in ("direct", "wrapper"):
        rows = [r for r in gt if r["kind"] == kind]
        caught = [r["id"] for r in rows if any(matches(r, h) for h in hits)]
        res[kind] = {"caught": len(caught), "n": len(rows), "ids": caught}
    negs = [r for r in gt if r["kind"].startswith("negative")]
    res["negatives_flagged"] = [r["id"] for r in negs if any(matches(r, h) for h in hits)]
    positives = [r for r in gt if r["kind"] in ("direct", "wrapper")]
    true_hits = [h for h in hits if any(matches(r, h) for r in positives)]
    res["flagged_locations"] = len(hits)
    res["precision"] = round(len(true_hits) / len(hits), 3) if hits else 0.0
    return res


def to_markdown(results: dict, semgrep_config: str, gt: list[dict]) -> str:
    n_pos = sum(r["kind"] in ("direct", "wrapper") for r in gt)
    n_neg = len(gt) - n_pos
    lines = [
        "# Eval: seeded targets", "",
        f"Sample: {n_pos} seeded bugs (6 direct, 6 through helpers) and {n_neg} safe cases "
        f"across 3 small Flask apps. **n is small; treat the numbers as indicative.**", "",
        f"Semgrep rules: {semgrep_config}. Match: same file and CWE, line within ±2.", "",
        "Caveat: the targets and the scanner were written by the same team, so this checks the "
        "approach, not real-world recall.", "",
        "| Tool | Direct bugs | Helper (wrapper) bugs | Safe cases wrongly flagged | Precision |",
        "|---|---|---|---|---|",
    ]
    for name, r in results.items():
        lines.append(f"| {name} | {r['direct']['caught']}/{r['direct']['n']} | "
                     f"{r['wrapper']['caught']}/{r['wrapper']['n']} | "
                     f"{len(r['negatives_flagged'])}/{n_neg} | {r['precision']:.2f} |")
    return "\n".join(lines) + "\n"


def main() -> dict:
    ap = argparse.ArgumentParser()
    ap.add_argument("--semgrep-config", default="p/python")
    ap.add_argument("--semgrep-label", default=None, help="how to name the rule set in the report")
    args = ap.parse_args()
    gt = json.loads((TARGETS / "ground_truth.json").read_text())
    results = {
        "Bandit": score(run_bandit(), gt),
        "Semgrep": score(run_semgrep(args.semgrep_config), gt),
        "ZeroSentinel (reachable findings)": score(run_ours(True), gt),
        "ZeroSentinel (all, incl. low-confidence)": score(run_ours(False), gt),
    }
    (ROOT / "eval/results.json").write_text(json.dumps(results, indent=2) + "\n")
    md = to_markdown(results, args.semgrep_label or args.semgrep_config, gt)
    (ROOT / "eval/results.md").write_text(md)
    print(md)
    return results


if __name__ == "__main__":
    main()
