#!/usr/bin/env bash
# Detection check against an installed Oreon Defense (system or user daemon).
# Uses shipped samples under /usr/share/oreon-defense/samples when present.
set -euo pipefail

SAMPLES_CANDIDATES=(
  "/usr/share/oreon-defense/samples"
  "$(cd "$(dirname "$0")/.." && pwd)/tests/samples"
)
SAMPLES=""
for d in "${SAMPLES_CANDIDATES[@]}"; do
  if [[ -f "$d/eicar.com" ]]; then SAMPLES="$d"; break; fi
done
if [[ -z "$SAMPLES" ]]; then
  echo "FAIL: EICAR sample not found (install package or run from source tree)"
  exit 1
fi

SOCK="${OREON_DEFENSE_SOCK:-}"
if [[ -z "$SOCK" ]]; then
  if [[ -S /run/oreon-defense/daemon.sock ]]; then
    SOCK=/run/oreon-defense/daemon.sock
  else
    SOCK="${XDG_DATA_HOME:-$HOME/.local/share}/oreon-defense/daemon.sock"
  fi
fi
if [[ ! -S "$SOCK" ]]; then
  echo "FAIL: daemon socket missing: $SOCK"
  echo "Start: systemctl start oreon-defense   OR   oreon-defense-daemon"
  exit 1
fi

mkdir -p "$HOME/Downloads"
TARGET="$HOME/Downloads/eicar-installed-$(date +%s).com"
cp -f "$SAMPLES/eicar.com" "$TARGET"
echo "dropped $TARGET"

python3 - <<PY
import json, os, socket, sys, time

sock_path = "$SOCK"
target = os.path.expanduser("$TARGET")

def rpc(method, params=None, timeout=8):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(sock_path)
    s.sendall((json.dumps({"id": method, "method": method, "params": params or {}}) + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(65536)
        if not chunk: break
        buf += chunk
    s.close()
    return json.loads(buf.split(b"\n", 1)[0].decode())

print("getStatus:", json.dumps(rpc("getStatus").get("result"), indent=2))

hit = False
for _ in range(30):
    time.sleep(0.3)
    q = rpc("getQuarantine").get("result", {}).get("items", [])
    th = rpc("getThreats").get("result", {}).get("threats", [])
    if any(target in i.get("originalPath", "") for i in q) or any("EICAR" in t.get("name","") for t in th):
        hit = True
        print("getQuarantine:", json.dumps({"items": q}, indent=2)[:1500])
        print("getThreats:", json.dumps({"threats": th}, indent=2)[:1500])
        break

if not hit:
    # Fall back to custom scan of the file itself
    r = rpc("startScan", {"type": "custom", "paths": [target]})
    print("fallback startScan:", r)
    for _ in range(40):
        time.sleep(0.25)
        p = rpc("getScanProgress").get("result", {})
        if not p.get("running", True):
            print("scan:", json.dumps(p, indent=2))
            break
    q = rpc("getQuarantine").get("result", {}).get("items", [])
    th = rpc("getThreats").get("result", {}).get("threats", [])
    print("getQuarantine:", json.dumps({"items": q}, indent=2)[:1500])
    print("getThreats:", json.dumps({"threats": th}, indent=2)[:1500])
    hit = any("EICAR" in t.get("name","") for t in th) or any(
        "eicar" in i.get("originalPath","").lower() or "EICAR" in i.get("threatName","") for i in q
    )

if not hit:
    print("FAIL: no EICAR threat observed")
    sys.exit(1)
print("test_installed_detection: ok")
PY
