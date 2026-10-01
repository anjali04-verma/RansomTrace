import { useEffect, useState } from "react";
import "./App.css";

const API = "http://192.168.56.101:8000/api/incidents";
const COLOR = { Critical: "#ef4444", High: "#f59e0b", Low: "#64748b" };
const SIGNALS = [
  { label: "Mass change", pts: 30, re: /files changed|mass_change/i },
  { label: ".locked extension", pts: 20, re: /locked/i },
  { label: "Ransom note", pts: 20, re: /ransom.?note/i },
  { label: "Shadow-copy delete", pts: 30, re: /shadow/i },
];
const fired = (reasons) => SIGNALS.filter((s) => reasons.some((r) => s.re.test(r)));

export default function App() {
  const [rows, setRows] = useState([]);
  const [online, setOnline] = useState(false);
  const [filter, setFilter] = useState("All");

  useEffect(() => {
    const load = () =>
      fetch(API).then((r) => r.json()).then((d) => { setRows(d); setOnline(true); })
        .catch(() => setOnline(false));
    load();
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, []);

  const count = (s) => rows.filter((r) => r.severity === s).length;
  const latest = rows[0];
  const shown = filter === "All" ? rows : rows.filter((r) => r.severity === filter);

  return (
    <div className="app">
      <div className="top">
        <div>
          <h1>Ransom<span>Trace</span></h1>
          <p>Multi-signal ransomware detection · Windows Server</p>
        </div>
        <div className={"pill " + (online ? "on" : "off")}>
          {online ? "● API connected" : "● API offline"}
        </div>
      </div>

      <div className="cards">
        <div className="card"><small>Total incidents</small><b>{rows.length}</b></div>
        <div className="card"><small>Critical</small><b style={{ color: COLOR.Critical }}>{count("Critical")}</b></div>
        <div className="card"><small>High</small><b style={{ color: COLOR.High }}>{count("High")}</b></div>
        <div className="card"><small>Low</small><b style={{ color: COLOR.Low }}>{count("Low")}</b></div>
      </div>

      {latest && (
        <div className="latest">
          <div className="ring" style={{ background: `conic-gradient(${COLOR[latest.severity]} ${latest.score * 3.6}deg, #243049 0)` }}>
            <div>{latest.score}</div>
          </div>
          <div className="meta">
            <h3>Latest incident · {latest.severity}</h3>
            <p>{latest.process} (PID {latest.pid}) · {latest.user} · {latest.files} files · {latest.time}</p>
            {latest.severity !== "Low" && <p>Response: <code>taskkill /F /PID {latest.pid}</code></p>}
            <div className="chips">
              {SIGNALS.map((s) => (
                <span key={s.label} className={"chip" + (fired(latest.reasons).includes(s) ? " hit" : "")}>
                  {s.label} +{s.pts}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="filters">
        {["All", "Critical", "High", "Low"].map((f) => (
          <button key={f} className={filter === f ? "act" : ""} onClick={() => setFilter(f)}>{f}</button>
        ))}
      </div>

      <table>
        <thead>
          <tr><th>Time</th><th>Process</th><th>Files</th><th>Score</th><th>Severity</th><th>Status</th><th>Signals fired</th></tr>
        </thead>
        <tbody>
          {shown.map((r, i) => (
            <tr key={i}>
              <td>{r.time}</td>
              <td>{r.process} ({r.pid})</td>
              <td>{r.files}</td>
              <td>{r.score}<div className="bar"><i style={{ width: r.score + "%", background: COLOR[r.severity] }} /></div></td>
              <td><span className="badge" style={{ background: COLOR[r.severity] }}>{r.severity}</span></td>
              <td>{r.status}</td>
              <td>{fired(r.reasons).map((s) => s.label).join(", ") || "none"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}