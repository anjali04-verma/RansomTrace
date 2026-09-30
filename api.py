import sqlite3
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])
DB = r"C:\RansomTrace\ransomtrace.db"
KEYS = ["time", "server", "process", "user", "pid", "files",
        "score", "severity", "status", "reasons"]

@app.get("/api/incidents")
def incidents():
    try:
        con = sqlite3.connect(DB)
        rows = con.execute("SELECT " + ",".join(KEYS) +
                           " FROM incidents ORDER BY time DESC LIMIT 20").fetchall()
        con.close()
    except sqlite3.Error:
        return []
    out = []
    for r in rows:
        d = dict(zip(KEYS, r))
        d["reasons"] = d["reasons"].split("; ") if d["reasons"] else []
        out.append(d)
    return out