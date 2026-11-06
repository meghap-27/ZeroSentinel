async function req(path, opts = {}) {
  const res = await fetch(`/api${path}`, opts);
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try { msg = (await res.json()).detail || msg; } catch { /* keep default */ }
    throw new Error(msg);
  }
  return res.json();
}

export const api = {
  scans: () => req("/scans"),
  scan: (id) => req(`/scans/${id}`),
  findings: (id) => req(`/scans/${id}/findings`),
  files: (id) => req(`/scans/${id}/files`),
  upload: (file) => {
    const body = new FormData();
    body.append("file", file);
    return req("/scans", { method: "POST", body });
  },
  snippet: (code) => req("/snippet", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, name: "Pasted snippet" }),
  }),
  setStatus: (sid, fid, status) => req(`/scans/${sid}/findings/${fid}`, {
    method: "PATCH", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  }),
};

export async function waitForScan(id, tries = 60) {
  for (let i = 0; i < tries; i++) {
    const s = await api.scan(id);
    if (s.status !== "running") return s;
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error("The scan is taking longer than 25 seconds. Refresh to check on it.");
}

export const CWE_NAME = {
  "CWE-78": "Command injection",
  "CWE-89": "SQL injection",
  "CWE-22": "Path traversal",
};

export function sevLevel(s) {
  if (s >= 9) return "critical";
  if (s >= 7) return "high";
  if (s >= 4) return "medium";
  return "low";
}

export const TIER_NAME = {
  "reachable": "Reachable from a route",
  "pattern-match": "Not reachable (low confidence)",
  "proof-confirmed": "Proof confirmed",
};
