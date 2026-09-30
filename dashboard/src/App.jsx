import { useEffect, useState } from "react";

const API = "http://192.168.56.101:8000/api/incidents";
const color = { Critical: "#c0392b", High: "#e67e22", Low: "#7f8c8d" };

export default function App() {
  const [rows, setRows] = useState([]);
  useEffect(() => {
    const load = () => fetch(API).then(r => r.json()).then(setRows).catch(() => {});
    load();
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, []);
  return (
    <div style={{ padding: 16, fontFamily: "sans-serif" }}>
      <h2>RansomTrace - Live Incidents</h2>
      <table border="1" cellPadding="6" style={{ borderCollapse: "collapse" }}>
        <thead><tr><th>Time</th><th>Server</th><th>Process</th><th>User</th>
          <th>Files</th><th>Score</th><th>Severity</th><th>Status</th><th>Reasons</th></tr></thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} style={{ background: color[r.severity] || "#7f8c8d", color: "white" }}>
              <td>{r.time}</td><td>{r.server}</td><td>{r.process} ({r.pid})</td>
              <td>{r.user}</td><td>{r.files}</td><td>{r.score}</td>
              <td>{r.severity}</td><td>{r.status}</td><td>{r.reasons.join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}