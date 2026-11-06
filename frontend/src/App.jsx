import React, { useEffect, useState } from "react";
import { api } from "./api.js";
import Home from "./Home.jsx";
import ScanView from "./ScanView.jsx";

function useHash() {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => {
    const on = () => setHash(window.location.hash);
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return hash;
}

function Shield() {
  return (
    <svg className="mark" viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 2 4 7v8c0 7.5 5 13 12 15 7-2 12-7.5 12-15V7z" />
      <path className="mark-trace" d="M16 9v6l-4 3v4M16 15l4 3" />
    </svg>
  );
}

export default function App() {
  const hash = useHash();
  const scanId = hash.startsWith("#/scan/") ? hash.slice(7) : null;
  const [scans, setScans] = useState([]);

  useEffect(() => { api.scans().then(setScans).catch(() => setScans([])); }, [hash]);

  return (
    <div className="app">
      <header className="topbar">
        <a className="brand" href="#/">
          <Shield />
          <span className="brand-name">Kavach</span>
          <span className="brand-sub">ZeroSentinel</span>
        </a>
        {scanId && <a className="topbar-link" href="#/">New scan</a>}
      </header>
      {scanId ? <ScanView scanId={scanId} /> : <Home scans={scans} />}
    </div>
  );
}
