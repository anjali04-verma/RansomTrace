"""RansomTrace detector.
Groups Sysmon events by ProcessGuid, adds points per behavior, and raises an
alert with reasons when the score reaches ALERT_AT. Run in an Administrator
PowerShell in the VM BEFORE starting simulator.py."""
import os
import re
import socket
import sqlite3
import time
from datetime import datetime

from sysmon_reader import read_events, latest_record_id

# ---------------- scoring table ----------------
SIGNALS = {
    "mass_change":      30,   # 50+ unique files changed within 30 s
    "locked_extension": 20,   # 20+ files renamed to .locked
    "ransom_note":      20,   # README_RESTORE.txt created
    "shadow_delete":    30,   # vssadmin delete shadows
}
MASS_MIN, LOCKED_MIN = 50, 20
ALERT_AT = 60                 # High from 60, Critical from 80
print("scoring table:", SIGNALS, " alert at:", ALERT_AT)
# ------------------------------------------------

DB = "ransomtrace.db"
WATCH = "c:\\data"          # only this folder is monitored
WINDOW = 30                 # seconds
SERVER = socket.gethostname()
# note: Sysmon shows two spaces in "vssadmin  delete shadows", so use \s+
SHADOW_RE = re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows", re.I)

parent = {}   # ProcessGuid -> ParentProcessGuid
procs = {}    # ProcessGuid -> state


def get(guid):
    if guid not in procs:
        procs[guid] = dict(name="?", user="?", pid="?", changes=[], seen=set(),
                           locked=set(), deleted=set(), note=False,
                           shadow=False, score=0)
    return procs[guid]


def max_in_window(times):
    best, j = 0, 0
    for i, t in enumerate(times):
        while (t - times[j]).total_seconds() > WINDOW:
            j += 1
        best = max(best, i - j + 1)
    return best


def score(p):
    found, reasons = [], []
    n = max_in_window(p["changes"])
    if n >= MASS_MIN:
        found.append("mass_change")
        reasons.append(f"{n} files changed within {WINDOW} seconds")
    if len(p["locked"]) >= LOCKED_MIN:
        found.append("locked_extension")
        reasons.append(f".locked extension on {len(p['locked'])} files")
    if p["note"]:
        found.append("ransom_note")
        reasons.append("Ransom note file created")
    if p["shadow"]:
        found.append("shadow_delete")
        reasons.append("Shadow-copy deletion (vssadmin delete shadows)")
    return sum(SIGNALS[s] for s in found), reasons, found


def severity(s):
    return "Critical" if s >= 80 else "High" if s >= ALERT_AT else "Low"


def init_db():
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS incidents(
        guid TEXT PRIMARY KEY, time TEXT, server TEXT, process TEXT,
        user TEXT, pid TEXT, files INTEGER, score INTEGER,
        severity TEXT, status TEXT, reasons TEXT)""")
    con.commit()
    return con


def alert(con, guid, p, pts, reasons):
    files = max(len(p["locked"]), len(p["deleted"]))
    sev = severity(pts)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "=" * 60)
    print(f"ALERT  {sev}  score {pts}/100")
    print(f"  Process : {p['name']} (PID {p['pid']})")
    print(f"  User    : {p['user']}")
    print(f"  Server  : {SERVER}")
    print(f"  Files   : {files}")
    print("  Reasons :")
    for r in reasons:
        print(f"    - {r}")
    print(f"  Response: taskkill /F /PID {p['pid']}")
    print("=" * 60)
    con.execute("""INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(guid) DO UPDATE SET files=excluded.files,
        score=excluded.score, severity=excluded.severity,
        reasons=excluded.reasons""",
                (guid, now, SERVER, p["name"], p["user"], p["pid"], files,
                 pts, sev, "Open", "; ".join(reasons)))
    con.commit()


def count_change(p, low, t):
    """Count each original file once, whether seen as create .locked or delete."""
    key = low[:-7] if low.endswith(".locked") else low
    if key not in p["seen"]:
        p["seen"].add(key)
        p["changes"].append(t)


def handle(ev):
    """Update state. Returns the set of process guids that changed."""
    eid = ev["EventID"]
    guid = ev.get("ProcessGuid")
    if not guid:
        return set()
    t = datetime.strptime(ev["UtcTime"], "%Y-%m-%d %H:%M:%S.%f")

    if eid == 1:
        parent[guid] = ev.get("ParentProcessGuid")
        p = get(guid)
        p["name"] = os.path.basename(ev.get("Image", "?"))
        p["user"] = ev.get("User", "?")
        p["pid"] = ev.get("ProcessId", "?")
        if not SHADOW_RE.search(ev.get("CommandLine", "")):
            return set()
        # walk up: vssadmin -> cmd -> python. Credit the ancestor(s) that
        # are doing file changes; if none yet, credit up to 3 ancestors.
        chain, g = [], parent.get(guid)
        while g and len(chain) < 3:
            chain.append(g)
            g = parent.get(g)
        with_files = [g for g in chain if get(g)["changes"]]
        hit = set(with_files or chain)
        for g in hit:
            get(g)["shadow"] = True
        return hit

    # Event 11 (file create) / 23 (file delete)
    path = ev.get("TargetFilename", "")
    low = path.lower()
    if not low.startswith(WATCH) or not os.path.splitext(low)[1]:
        return set()               # ignore other folders and folder events
    p = get(guid)
    p["name"] = os.path.basename(ev.get("Image", "?"))
    p["user"] = ev.get("User", "?")
    p["pid"] = ev.get("ProcessId", "?")
    fname = os.path.basename(low)
    if eid == 11:
        if low.endswith(".locked"):
            p["locked"].add(low)
            count_change(p, low, t)
        elif "readme" in fname or "restore" in fname:
            p["note"] = True
        # plain new files (setup of dummy data) are not counted as changes
    elif eid == 23:
        p["deleted"].add(low)
        count_change(p, low, t)
    return {guid}


def summary():
    print("\nSESSION SUMMARY")
    shown = False
    for g, p in procs.items():
        pts, _, found = score(p)
        if p["changes"] or p["note"] or p["shadow"]:
            shown = True
            print(f"  {p['name']} (PID {p['pid']}) score={pts}/100 {severity(pts)} signals={found}")
    if not shown:
        print("  no suspicious activity, all processes score 0")


def main():
    con = init_db()
    last = latest_record_id()
    print(f"RansomTrace detector running on {SERVER}. Watching {WATCH}. Ctrl+C to stop.")
    try:
        while True:
            for ev in read_events(last):
                last = max(last, ev["RecordID"])
                for g in handle(ev):
                    p = get(g)
                    pts, reasons, _ = score(p)
                    if pts >= ALERT_AT and pts > p["score"]:
                        p["score"] = pts
                        alert(con, g, p, pts, reasons)
            time.sleep(2)
    except KeyboardInterrupt:
        summary()
        print("stopped")


if __name__ == "__main__":
    main()