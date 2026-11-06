import React, { useEffect, useMemo, useState } from "react";
import { api, CWE_NAME, sevLevel } from "./api.js";
import Detail from "./Detail.jsx";

const FILTERS = {
  cwe: ["all", "CWE-78", "CWE-89", "CWE-22"],
  level: ["all", "critical", "high", "medium", "low"],
  tier: ["all", "reachable", "pattern-match"],
  status: ["all", "open", "fixed", "accepted"],
};
const FILTER_LABEL = { cwe: "Bug class", level: "Severity", tier: "Confidence", status: "Status" };
const OPTION_LABEL = { all: "All", "pattern-match": "Not reachable", reachable: "Reachable", ...CWE_NAME };

function Summary({ scan, findings }) {
  const open = findings.filter((f) => f.status === "open");
  const levels = ["critical", "high", "medium", "low"].map((l) => [l, open.filter((f) => sevLevel(f.severity) === l).length]);
  const helper = findings.filter((f) => f.detector === "taint-wrapper").length;
  return (
    <div className="summary">
      <div className="summary-head">
        <h1>{scan.name}</h1>
        <p>{scan.files_scanned} Python files scanned in {scan.duration < 1 ? `${Math.round(scan.duration * 1000)} ms` : `${scan.duration.toFixed(1)} s`}{scan.files_skipped ? `, ${scan.files_skipped} other files skipped` : ""}</p>
      </div>
      <div className="summary-stats">
        <p className="stat-lead"><strong>{open.length}</strong> open findings</p>
        <div className="sevbar" aria-label="Open findings by severity">
          {levels.filter(([, n]) => n).map(([l, n]) => (
            <span key={l} className={`sevbar-seg sev-${l}`} style={{ flexGrow: n }}>{n} {l}</span>
          ))}
        </div>
        <p className="stat-note">{helper} found only by following input through helper functions</p>
      </div>
    </div>
  );
}

export default function ScanView({ scanId }) {
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [files, setFiles] = useState({});
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState({ cwe: "all", level: "all", tier: "all", status: "all" });
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([api.scan(scanId), api.findings(scanId), api.files(scanId)])
      .then(([s, f, fl]) => { setScan(s); setFindings(f); setFiles(fl); setSelected(f[0]?.id ?? null); })
      .catch((e) => setError(e.message));
  }, [scanId]);

  const shown = useMemo(() => findings.filter((f) =>
    (filter.cwe === "all" || f.cwe === filter.cwe) &&
    (filter.level === "all" || sevLevel(f.severity) === filter.level) &&
    (filter.tier === "all" || f.confidence_tier === filter.tier) &&
    (filter.status === "all" || f.status === filter.status)), [findings, filter]);

  if (error) return <main className="scan"><p className="error">{error}</p></main>;
  if (!scan) return <main className="scan"><p className="muted">Loading scan…</p></main>;

  const current = findings.find((f) => f.id === selected);
  const onUpdate = (nf) => setFindings((all) => all.map((f) => (f.id === nf.id ? nf : f)));

  return (
    <main className="scan">
      <Summary scan={scan} findings={findings} />
      <div className="split">
        <section className="list" aria-label="Findings">
          <div className="filters">
            {Object.entries(FILTERS).map(([key, opts]) => (
              <label key={key}>
                <span>{FILTER_LABEL[key]}</span>
                <select value={filter[key]} onChange={(e) => setFilter({ ...filter, [key]: e.target.value })}>
                  {opts.map((o) => <option key={o} value={o}>{OPTION_LABEL[o] || o[0].toUpperCase() + o.slice(1)}</option>)}
                </select>
              </label>
            ))}
          </div>
          {shown.length === 0 && <p className="muted pad">No findings match these filters. Set a filter back to All to see more.</p>}
          <ul className="rows">
            {shown.map((f) => (
              <li key={f.id}>
                <button className={`row ${f.id === selected ? "is-selected" : ""} ${f.status !== "open" ? "is-closed" : ""}`}
                        onClick={() => setSelected(f.id)}>
                  <span className={`score sev-${sevLevel(f.severity)}`}>{f.severity.toFixed(1)}</span>
                  <span className="row-main">
                    <span className="row-title">{CWE_NAME[f.cwe]}{f.detector === "taint-wrapper" && <span className="tag">through {f.path.length - 2} helper{f.path.length > 3 ? "s" : ""}</span>}</span>
                    <span className="row-loc">{f.file}:{f.line}</span>
                  </span>
                  <span className={`row-status st-${f.status}`}>{f.status === "open" ? (f.confidence_tier === "reachable" ? "" : "unreachable") : f.status}</span>
                </button>
              </li>
            ))}
          </ul>
        </section>
        {current ? <Detail key={current.id} finding={current} files={files} onUpdate={onUpdate} />
                 : <section className="detail"><p className="muted pad">This scan found no command injection, SQL injection or path traversal.</p></section>}
      </div>
    </main>
  );
}
