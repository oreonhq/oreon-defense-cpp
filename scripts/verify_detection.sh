#!/usr/bin/env bash
# End-to-end detection check (dev tree or local build).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/build/test_rules"
RULES="$ROOT/data/rules/starter-rules.yaml"
SAMPLES="$ROOT/tests/samples"
DAEMON="${OREON_DAEMON:-$ROOT/build/oreon-defense-daemon}"

if [[ ! -x "$BIN" ]]; then
  echo "Building tests first..."
  "$ROOT/scripts/build.sh"
fi

echo "== Rule engine checks =="
"$BIN" "$RULES" "$SAMPLES"

if [[ ! -x "$DAEMON" ]]; then
  echo "WARN: daemon binary missing at $DAEMON; rule checks only"
  echo "verify_detection: ok (rules only)"
  exit 0
fi

DATA="${XDG_DATA_HOME:-$HOME/.local/share}/oreon-defense"
CFGDIR="${XDG_CONFIG_HOME:-$HOME/.config}/oreon-defense"
mkdir -p "$DATA/rules" "$DATA/quarantine" "$CFGDIR" "$HOME/Downloads"
cp -f "$RULES" "$DATA/rules/starter-rules.yaml"

# Fresh state for a deterministic live test
rm -f "$DATA/daemon.sock"
rm -rf "$DATA/quarantine/data" "$DATA/quarantine/meta"
mkdir -p "$DATA/quarantine/data" "$DATA/quarantine/meta"
: > "$DATA/events.jsonl"

pkill -f '[o]reon-defense-daemon' 2>/dev/null || true
sleep 0.4

"$DAEMON" &
DPID=$!
cleanup() {
  kill "$DPID" 2>/dev/null || true
  wait "$DPID" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for socket
SOCK="$DATA/daemon.sock"
for i in $(seq 1 30); do
  [[ -S "$SOCK" ]] && break
  sleep 0.2
done
if [[ ! -S "$SOCK" ]]; then
  echo "FAIL: daemon socket not ready"
  exit 1
fi

python3 - <<PY
import json, os, socket, sys, time, shutil

sock_path = os.path.expanduser("$SOCK")
samples = "$SAMPLES"
downloads = os.path.expanduser("~/Downloads")
os.makedirs(downloads, exist_ok=True)

def rpc(method, params=None, timeout=5):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(sock_path)
    req = {"id": method, "method": method, "params": params or {}}
    s.sendall((json.dumps(req) + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    line = buf.split(b"\n", 1)[0]
    return json.loads(line.decode())

st = rpc("getStatus")
assert st.get("ok"), st
print("getStatus:", json.dumps(st.get("result"), indent=2))

# --- realtime drop into Downloads ---
target = os.path.join(downloads, f"eicar-verify-{int(time.time())}.com")
shutil.copyfile(os.path.join(samples, "eicar.com"), target)
print("dropped", target)

hit = False
for _ in range(25):
    time.sleep(0.25)
    q = rpc("getQuarantine")
    items = q.get("result", {}).get("items", [])
    th = rpc("getThreats").get("result", {}).get("threats", [])
    if any(target in i.get("originalPath", "") for i in items) or any(
        "EICAR" in t.get("name", "") for t in th
    ):
        hit = True
        print("realtime quarantine items:", len(items), "threats:", len(th))
        print("getQuarantine:", json.dumps(q.get("result"), indent=2)[:1200])
        print("getThreats:", json.dumps({"threats": th}, indent=2)[:1200])
        break

if not hit:
    print("FAIL: realtime EICAR drop did not produce threat/quarantine")
    sys.exit(1)

# --- custom scan of a folder with a fresh EICAR ---
scan_dir = os.path.join(downloads, f"oreon-scan-{int(time.time())}")
os.makedirs(scan_dir, exist_ok=True)
scan_file = os.path.join(scan_dir, "eicar.com")
shutil.copyfile(os.path.join(samples, "eicar.com"), scan_file)
# Disable realtime briefly? Not needed; scan should still report.
r = rpc("startScan", {"type": "custom", "paths": [scan_dir]})
assert r.get("ok"), r
print("startScan:", r.get("result"))

done = False
for _ in range(40):
    time.sleep(0.25)
    p = rpc("getScanProgress").get("result", {})
    if not p.get("running", True):
        done = True
        print("scan progress:", json.dumps(p, indent=2))
        break

if not done:
    print("FAIL: scan did not finish")
    sys.exit(1)

th = rpc("getThreats").get("result", {}).get("threats", [])
q = rpc("getQuarantine").get("result", {}).get("items", [])
scan_hit = any("EICAR" in t.get("name", "") for t in th) or any(
    "eicar" in i.get("originalPath", "").lower() or "eicar" in i.get("threatName", "").lower()
    for i in q
)
print("after scan threats:", len(th), "quarantine:", len(q))
if not scan_hit:
    print("FAIL: custom scan did not report EICAR")
    sys.exit(1)

print("live detection ok")
PY

echo "verify_detection: ok"
