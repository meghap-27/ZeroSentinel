import React, { useRef, useState } from "react";
import { api, waitForScan } from "./api.js";

function ago(ts) {
  const s = Math.round(Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  return `${Math.round(s / 3600)} h ago`;
}

export default function Home({ scans }) {
  const input = useRef(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [over, setOver] = useState(false);
  const [code, setCode] = useState("");

  async function run(start, label) {
    setError("");
    setBusy(label);
    try {
      const { id } = await start();
      const scan = await waitForScan(id);
      if (scan.status === "failed") throw new Error(`The scan failed: ${scan.error}`);
      window.location.hash = `#/scan/${id}`;
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  }

  function onFiles(files) {
    const f = files?.[0];
    if (!f) return;
    if (!f.name.endsWith(".zip")) { setError("Upload a .zip of your Flask project."); return; }
    run(() => api.upload(f), `Scanning ${f.name}`);
  }

  return (
    <main className="home">
      <section className="intro">
        <h1>Find the injection bugs your helpers hide.</h1>
        <p>
          Kavach follows user input from each Flask route through your own helper functions
          to the call that runs a command, a SQL query or opens a file, and shows you every step.
        </p>
      </section>

      <section className="start">
        <div
          className={`drop ${over ? "is-over" : ""} ${busy ? "is-busy" : ""}`}
          onDragOver={(e) => { e.preventDefault(); setOver(true); }}
          onDragLeave={() => setOver(false)}
          onDrop={(e) => { e.preventDefault(); setOver(false); onFiles(e.dataTransfer.files); }}
        >
          <input ref={input} type="file" accept=".zip" hidden data-testid="zip-input"
                 onChange={(e) => onFiles(e.target.files)} />
          {busy ? (
            <p className="drop-busy"><span className="pulse" />{busy}…</p>
          ) : (
            <>
              <p className="drop-title">Drop a zip of your Flask project here</p>
              <p className="drop-hint">Python files only. Virtualenvs, tests and vendored code are skipped. Up to 50 MB.</p>
              <button className="btn" onClick={() => input.current.click()}>Choose zip file</button>
            </>
          )}
        </div>

        <div className="snippet">
          <label htmlFor="snippet">Or paste a route or function</label>
          <textarea id="snippet" spellCheck="false" value={code} onChange={(e) => setCode(e.target.value)}
                    placeholder={"@app.route('/run')\ndef run():\n    os.system('ls ' + request.args['dir'])"} />
          <button className="btn btn-quiet" disabled={!code.trim() || !!busy}
                  onClick={() => run(() => api.snippet(code), "Scanning snippet")}>Scan snippet</button>
        </div>
        {error && <p className="error" role="alert">{error}</p>}
      </section>

      {scans.length > 0 && (
        <section className="recent">
          <h2>Recent scans</h2>
          <ul>
            {scans.slice(0, 6).map((s) => (
              <li key={s.id}>
                <a href={`#/scan/${s.id}`}>
                  <span className="recent-name">{s.name}</span>
                  <span className="recent-meta">{s.status === "done" ? `${s.files_scanned} files` : s.status}, {ago(s.created)}</span>
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}
    </main>
  );
}
