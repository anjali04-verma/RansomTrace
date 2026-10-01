# RansomTrace

Detects ransomware on a Windows Server by reading Sysmon events, grouping them
per process, and combining several behaviors into an explained risk score,
shown on a React dashboard.

## Why it is different
A basic detector counts file changes (for example 100 in 30 seconds). A slow
attack stays under that count. RansomTrace correlates several behaviors of the
same process, so a 30-file slow run still scores 70/100 (High) and lists the
reasons.

## Scoring table
| Signal | Points |
|---|---|
| 50+ unique files changed within 30 seconds | 30 |
| .locked extension on 20+ files | 20 |
| Ransom note file created | 20 |
| Shadow-copy deletion (vssadmin delete shadows) | 30 |

Alert at 60 or more (High). Critical at 80 or more.

## Architecture
Sysmon (Event IDs 1, 3, 11, 23) -> detector.py (score per process) -> SQLite
(`ransomtrace.db`) -> FastAPI (`api.py`) -> React dashboard (`dashboard/`).

## Files
- `simulator.py`: harmless ransomware simulator (fast: 500 files, slow: 30 files)
- `detector.py` and `sysmon_reader.py`: detector and scorer
- `baseline.py`: basic file-count detector used for comparison
- `receiver.py`: Flask receiver for the fake key upload (runs on the laptop)
- `api.py`: FastAPI endpoint `/api/incidents`
- `dashboard/`: React dashboard
- `evidence/`: proof screenshots and outputs

## How to run
Windows Server VM (Administrator PowerShell, `C:\RansomTrace`):
```
python detector.py
python baseline.py
python simulator.py slow      # or: fast
uvicorn api:app --host 0.0.0.0 --port 8000
```
Laptop:
```
python receiver.py
cd dashboard
npm install
npm run dev
```

## Results
| Run | Baseline counter | RansomTrace |
|---|---|---|
| Slow (30 files) | silent | 70/100 High |
| Fast (500 files) | alert | 100/100 Critical |
| Quiet session | silent | 0/100 Low |

## Setup notes
- Because of limited laptop RAM, Wazuh and the Ubuntu VM were skipped. The
  mentor-approved fallback was used: the detector reads Sysmon directly with Python.
- Wireshark and the Flask receiver run on the laptop (host-only network).
- Limitation: note and extension names match this simulator (`.locked`, README/restore).

## Safety
The simulator only touches `C:\Data` and must be run only in an isolated test VM
with a snapshot taken first. The key it sends is fake.