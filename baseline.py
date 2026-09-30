"""Basic version: count file changes in C:\\Data per 30 seconds and alert at 100.
No process correlation, no reasons. Used to show what the simple approach misses."""
import os
import time
from collections import deque
from datetime import datetime

from sysmon_reader import read_events, latest_record_id

WATCH = "c:\\data"
WINDOW = 30
THRESHOLD = 100


def main():
    times = deque()
    alerted = False
    last = latest_record_id()
    print(f"Baseline counter running. Alert at {THRESHOLD} file changes in {WINDOW}s. Ctrl+C to stop.")
    try:
        while True:
            for ev in read_events(last):
                last = max(last, ev["RecordID"])
                if ev["EventID"] not in (11, 23):
                    continue
                low = ev.get("TargetFilename", "").lower()
                if not low.startswith(WATCH) or not os.path.splitext(low)[1]:
                    continue
                t = datetime.strptime(ev["UtcTime"], "%Y-%m-%d %H:%M:%S.%f")
                times.append(t)
                while (t - times[0]).total_seconds() > WINDOW:
                    times.popleft()
                if len(times) >= THRESHOLD and not alerted:
                    alerted = True
                    print(f"BASELINE ALERT: {len(times)} file changes in {WINDOW}s (ransomware detected)")
            time.sleep(2)
    except KeyboardInterrupt:
        print("stopped. alerted =", alerted)


if __name__ == "__main__":
    main()