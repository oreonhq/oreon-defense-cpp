#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

SAMPLES=""
for d in /usr/share/oreon-defense/samples "$ROOT/tests/samples"; do
  [[ -f "$d/eicar.com" ]] && { SAMPLES="$d"; break; }
done
[[ -n "$SAMPLES" ]] || { echo "FAIL: EICAR sample not found (install the package or run from the source tree)"; exit 1; }

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
  echo "Start it with: systemctl start oreon-defense (or run oreon-defense-daemon)"
  exit 1
fi

if [[ "$HOME" == /home/* ]]; then DROP="$HOME/Downloads"; else DROP="/tmp"; fi
mkdir -p "$DROP"

export SOCK SAMPLES DROP
python3 - <<'PY'
import json, os, shutil, socket, subprocess, sys, time

SOCK = os.environ["SOCK"]; SAMPLES = os.environ["SAMPLES"]; DROP = os.environ["DROP"]
ROOT = os.geteuid() == 0
fails = []

def rpc(method, params=None, preexec=None):
    req = json.dumps({"id": method, "method": method, "params": params or {}}) + "\n"
    if preexec:
        code = ("import json,socket,sys\n"
                "s=socket.socket(socket.AF_UNIX);s.settimeout(20);s.connect(sys.argv[1]);s.sendall(sys.argv[2].encode())\n"
                "f=s.makefile('r')\n"
                "for l in f:\n"
                " if '\"event\"' not in l: print(l.strip()); break\n")
        out = subprocess.run(preexec + [sys.executable, "-c", code, SOCK, req],
                             capture_output=True, text=True, timeout=30)
        return json.loads(out.stdout.strip() or "{}")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(SOCK)
    s.sendall(req.encode())
    for line in s.makefile("r"):
        j = json.loads(line)
        if "event" not in j:
            s.close()
            return j
    return {}

def check(cond, what):
    print(("ok:   " if cond else "FAIL: ") + what)
    if not cond:
        fails.append(what)

def wait(pred, secs):
    end = time.time() + secs
    while time.time() < end:
        r = pred()
        if r:
            return r
        time.sleep(0.5)
    return None

st = rpc("getStatus")
check(st.get("ok"), "daemon answers on " + SOCK)
s = st.get("result", {})
c = s.get("clamav", {})
print("      version %s" % s.get("version"))
print("      ClamAV: available=%s sigs=%s main=%s daily=%s %s" % (c.get("available"), c.get("signatures"),
      c.get("mainVersion"), c.get("dailyVersion"), c.get("error", "")))
oa = s.get("onAccess", {})
print("      on-access: mode=%s marks=%s %s" % (oa.get("mode"), oa.get("markMode"), oa.get("error", "")))
print("      process monitor: %s" % s.get("processMonitor", {}).get("mode"))
nb = s.get("networkBlocking", {})
print("      network blocking: active=%s addresses=%s %s" % (nb.get("active"), nb.get("count"), nb.get("error", "")))
r = s.get("rules", {})
print("      rules: version=%s count=%s lastUpdate=%s %s" % (r.get("version"), r.get("count"), r.get("lastUpdate"), r.get("lastError", "")))
check(c.get("available"), "ClamAV engine loaded")
check(s.get("fileRealtime") is True, "real-time protection on")

target = os.path.join(DROP, "eicar-installed-%d.com" % int(time.time()))
shutil.copyfile(os.path.join(SAMPLES, "eicar.com"), target)
print("      dropped " + target)
def found():
    th = rpc("getThreats").get("result", {}).get("threats", [])
    return [t for t in th if t.get("path") == target]
hit = wait(found, 20)
check(bool(hit), "EICAR drop detected")
if hit:
    check("eicar" in hit[0]["name"].lower(), "detected as " + hit[0]["name"] + " by " + hit[0].get("engine", "?"))
    check(not os.path.exists(target), "EICAR drop moved to quarantine")
if os.path.exists(target):
    os.remove(target)

if hit and hit[0].get("quarantineId"):
    qid = hit[0]["quarantineId"]
    rdel = rpc("deleteQuarantine", {"id": qid})
    check(rdel.get("ok"), "quarantine delete works with no password")
    gone = not [i for i in rpc("getQuarantine")["result"]["items"] if i.get("id") == qid]
    check(gone, "deleted item removed from the quarantine list")

if shutil.which("bash"):
    rsh = subprocess.Popen(["bash", "-c", "TARGET=/dev/tcp/127.0.0.1/4444; while :; do sleep 1; done"])
    rdead = wait(lambda: rsh.poll() is not None, 15)
    check(bool(rdead), "reverse shell pattern (/dev/tcp) stopped")
    if not rdead:
        rsh.kill()

if oa.get("mode") == "fanotify":
    f = "/var/tmp/oreon-onaccess-%d.txt" % int(time.time())
    with open(f, "w") as fh:
        fh.write(open(os.path.join(SAMPLES, "eicar.com")).read())
    r2 = subprocess.run(["cat", f], capture_output=True, text=True)
    check(r2.returncode != 0 and "not permitted" in r2.stderr.lower(), "opening EICAR is blocked")
    q = wait(lambda: [i for i in rpc("getQuarantine")["result"]["items"] if i.get("originalPath") == f], 10)
    check(bool(q), "blocked file quarantined")
    if os.path.exists(f):
        os.remove(f)
else:
    print("skip: on-access blocking is not active")

before = rpc("getStatus")["result"]["rules"].get("lastCheck", 0)
u = rpc("updateRules", {})
if u.get("ok"):
    rs = wait(lambda: (lambda x: x if x.get("lastCheck", 0) > before and not x.get("running") else None)(
        rpc("getStatus")["result"]["rules"]), 60)
    if rs is None:
        check(False, "rule update finished")
    elif rs.get("lastError"):
        print("warn: rule update failed: " + rs["lastError"])
    else:
        check(True, "rule update ok, version %s" % rs.get("version"))
else:
    print("warn: rule update not started: %s" % u.get("error"))

if ROOT:
    if nb.get("active"):
        t = subprocess.run(["nft", "list", "table", "inet", "oreon_defense"], capture_output=True, text=True)
        check(t.returncode == 0, "nftables table inet oreon_defense present")
        b = rpc("blockIp", {"ip": "203.0.113.99", "reason": "installed test"})
        check(b.get("ok"), "blockIp 203.0.113.99")
        out = subprocess.run(["nft", "list", "set", "inet", "oreon_defense", "blocklist4"], capture_output=True, text=True).stdout
        check("203.0.113.99" in out, "address present in nftables set")
        check(rpc("unblockIp", {"ip": "203.0.113.99"}).get("ok"), "unblockIp 203.0.113.99")
    else:
        print("skip: network blocking is not active")
    if shutil.which("setpriv"):
        nobody = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"]
        for m, p in (("setOptions", {"killMalicious": False}), ("blockIp", {"ip": "203.0.113.98"}),
                     ("setProtection", {"fileRealtime": False}), ("restore", {"id": "x"})):
            r3 = rpc(m, p, preexec=nobody)
            check(not r3.get("ok") and r3.get("code") == "EPERM", "unprivileged caller refused: " + m)
        check(rpc("getStatus", preexec=nobody).get("ok"), "unprivileged caller can read status")
else:
    w = rpc("whoami").get("result", {})
    print("      caller uid=%s privileged=%s (run as root for nftables and permission checks)" % (w.get("uid"), w.get("privileged")))

if fails:
    print("\n%d check(s) failed" % len(fails))
    sys.exit(1)
print("\ninstalled checks ok")
PY
