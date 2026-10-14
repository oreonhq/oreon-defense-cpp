#!/bin/sh
SOCK="${OREON_DEFENSE_SOCK:-/run/oreon-defense/daemon.sock}"
if [ ! -S "$SOCK" ]; then
  SOCK="$HOME/.local/share/oreon-defense/daemon.sock"
fi
python3 - <<PY
import socket, json, sys
sock_path = "$SOCK"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect(sock_path)
except Exception as e:
    print("connect failed:", e, file=sys.stderr)
    sys.exit(1)
req = json.dumps({"id":"1","method":"startScan","params":{"type":"quick"}}) + "\n"
s.sendall(req.encode())
print(s.recv(4096).decode())
s.close()
PY
