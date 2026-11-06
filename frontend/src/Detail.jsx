import React, { useMemo, useState } from "react";
import { api, CWE_NAME, sevLevel, TIER_NAME } from "./api.js";

const FACTOR_LABEL = {
  base: "Bug class",
  reachable: "Reachable from a route",
  public_route: "Route needs no login",
  confidence: "Confidence",
  sanitizer_present: "Partial sanitizer",
};

function locate(step, finding, files) {
  if (step === finding.path[finding.path.length - 1]) return { file: finding.file, line: finding.line, sink: true };
  const name = step.replace(/\(\)$/, "");
  const re = new RegExp(`^\\s*(async\\s+)?def\\s+${name}\\s*\\(`);
  for (const [file, text] of Object.entries(files)) {
    const idx = text.split("\n").findIndex((l) => re.test(l));
    if (idx >= 0) return { file, line: idx + 1, sink: false };
  }
  return null;
}

function Code({ files, at }) {
  if (!at || !files[at.file]) return <p className="muted pad">Source for this step is not in the upload.</p>;
  const lines = files[at.file].split("\n");
  const from = Math.max(0, at.line - 4);
  const to = Math.min(lines.length, at.line + (at.sink ? 2 : 6));
  return (
    <figure className="code">
      <figcaption>{at.file}</figcaption>
      <pre>
        {lines.slice(from, to).map((l, i) => {
          const n = from + i + 1;
          return (
            <div key={n} className={`code-line ${n === at.line ? (at.sink ? "is-sink" : "is-step") : ""}`}>
              <span className="ln">{n}</span><code>{l || " "}</code>
            </div>
          );
        })}
      </pre>
    </figure>
  );
}

export default function Detail({ finding: f, files, onUpdate }) {
  const steps = useMemo(() => f.path.map((s) => ({ step: s, at: locate(s, f, files) })), [f, files]);
  const [active, setActive] = useState(steps.length - 1);
  const [saving, setSaving] = useState(false);
  const [note, setNote] = useState("");

  async function changeStatus(status) {
    setSaving(true);
    setNote("");
    try {
      onUpdate(await api.setStatus(f.scan_id, f.id, status));
      setNote(status === "open" ? "Reopened." : `Marked as ${status}.`);
    } catch (e) {
      setNote(`Status not saved: ${e.message}`);
    } finally {
      setSaving(false);
    }
  }

  const level = sevLevel(f.severity);
  return (
    <section className="detail" aria-label="Finding detail">
      <header className="detail-head">
        <div>
          <h2>{CWE_NAME[f.cwe]} in {f.path[f.path.length - 2]}</h2>
          <p className="detail-sub">{f.cwe}, {f.owasp}. {TIER_NAME[f.confidence_tier]}.</p>
        </div>
        <div className={`badge sev-${level}`}><strong>{f.severity.toFixed(1)}</strong><span>{level}</span></div>
      </header>

      <div className="trace-wrap">
        <div className="trace" role="list" aria-label="Path from user input to the dangerous call">
          <div className="trace-source" role="listitem">
            <span className="node node-source" />
            <span><span className="trace-k">User input</span>{f.source}</span>
          </div>
          {steps.map((s, i) => {
            const last = i === steps.length - 1;
            return (
              <button key={i} role="listitem" className={`trace-step ${i === active ? "is-active" : ""} ${last ? "is-sink" : ""}`}
                      onClick={() => setActive(i)}>
                <span className={`node ${last ? "node-sink" : ""}`} />
                <span className="trace-name">{s.step}</span>
                <span className="trace-loc">{s.at ? `${s.at.file}:${s.at.line}` : "not in upload"}</span>
              </button>
            );
          })}
        </div>
        <Code files={files} at={steps[active]?.at} />
      </div>

      <div className="detail-grid">
        <div>
          <h3>How to fix it</h3>
          <p className="fix">{f.fix_suggestion}</p>
        </div>
        <div>
          <h3>Why it scores {f.severity.toFixed(1)}</h3>
          <dl className="factors">
            {Object.entries(f.severity_factors).filter(([, v]) => v !== 0).map(([k, v]) => (
              <div key={k}><dt>{FACTOR_LABEL[k] || k}</dt><dd>{v > 0 ? "+" : ""}{v.toFixed(1)}</dd></div>
            ))}
          </dl>
        </div>
      </div>

      <footer className="detail-foot">
        <label>
          <span>Status</span>
          <select value={f.status} disabled={saving} onChange={(e) => changeStatus(e.target.value)} data-testid="status">
            <option value="open">Open</option>
            <option value="fixed">Fixed</option>
            <option value="accepted">Accepted risk</option>
          </select>
        </label>
        <span className="note" aria-live="polite">{note}</span>
      </footer>
    </section>
  );
}
