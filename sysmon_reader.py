"""Reads Sysmon events (ID 1, 11, 23) from the Windows Event Log using wevtutil.
Run from an Administrator PowerShell inside the Windows VM."""
import subprocess
import xml.etree.ElementTree as ET

LOG = "Microsoft-Windows-Sysmon/Operational"
NS = "{http://schemas.microsoft.com/win/2004/08/Events/event}"


def _run(args):
    r = subprocess.run(["wevtutil", "qe", LOG, *args, "/f:xml"],
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print("wevtutil error (run as Administrator?):", r.stderr.strip())
    return r.stdout


def _parse(xml_text):
    if not xml_text.strip():
        return []
    root = ET.fromstring("<Events>" + xml_text + "</Events>")
    events = []
    for e in root:
        d = {}
        for child in e:
            tag = child.tag.rsplit("}", 1)[-1]      # ignore XML namespace
            if tag == "System":
                for x in child:
                    xt = x.tag.rsplit("}", 1)[-1]
                    if xt == "EventID":
                        d["EventID"] = int(x.text)
                    elif xt == "EventRecordID":
                        d["RecordID"] = int(x.text)
            elif tag == "EventData":
                for x in child:
                    d[x.get("Name")] = x.text or ""
        if "EventID" in d and "RecordID" in d:
            events.append(d)
    events.sort(key=lambda x: x["RecordID"])
    return events


def latest_record_id():
    """Newest record in the log, so we only look at events created after start."""
    evs = _parse(_run(["/c:1", "/rd:true"]))
    return max((e["RecordID"] for e in evs), default=0)


def read_events(last_id):
    q = ("*[System[(EventID=1 or EventID=11 or EventID=23) "
         f"and (EventRecordID>{last_id})]]")
    return _parse(_run([f"/q:{q}", "/c:5000"]))