#include "ChangeAssess.hpp"
#include "SystemTrust.hpp"
#include "WriteTracker.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <climits>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>

namespace fs = std::filesystem;
using namespace oreon;
using trust::ActorTrust;

static int failures = 0;
static void check(bool c, const std::string& m) { if (!c) { std::cerr << "FAIL: " << m << "\n"; ++failures; } }
static std::string noRpm(const std::string&, const std::string&) { return {}; }

static std::string proc;
static void fakeProc(int pid, int ppid, int uid, const std::string& exe, const std::string& cmdline,
                     const std::string& root = "") {
  const std::string d = proc + "/" + std::to_string(pid);
  fs::remove_all(d);
  fs::create_directories(d);
  std::ofstream(d + "/status") << "Name:\tx\nPPid:\t" << ppid << "\nUid:\t" << uid << "\t" << uid << "\t"
                               << uid << "\t" << uid << "\n";
  std::ofstream(d + "/comm") << "x\n";
  std::ofstream c(d + "/cmdline");
  for (char ch : cmdline) c << (ch == ' ' ? '\0' : ch);
  c << '\0';
  fs::create_symlink(exe, d + "/exe");
  if (!root.empty()) fs::create_symlink(root, d + "/root");
}

static std::string sysExe() {
  for (const char* c : {"/usr/bin/true", "/bin/true", "/usr/bin/ls"}) {
    char r[PATH_MAX];
    if (realpath(c, r) && trust::classifySystemExe(r) != trust::SystemExe::No) return r;
  }
  return {};
}
static std::string setuidExe() {
  for (const char* c : {"/usr/bin/pkexec", "/usr/bin/sudo", "/usr/bin/chfn", "/usr/bin/su", "/usr/bin/passwd",
                        "/usr/bin/gpasswd", "/usr/bin/mount", "/bin/su"}) {
    struct stat st{};
    char r[PATH_MAX];
    if (realpath(c, r) && stat(r, &st) == 0 && st.st_uid == 0 && (st.st_mode & S_ISUID) &&
        trust::classifySystemExe(r) != trust::SystemExe::No)
      return r;
  }
  return {};
}
static std::string bashExe() {
  for (const char* c : {"/usr/bin/bash", "/bin/bash"}) {
    char r[PATH_MAX];
    if (realpath(c, r)) return r;
  }
  return {};
}

static change::Verdict judge(const std::string& path, const std::string& before, const std::string& after,
                             int pid) {
  change::Event e;
  e.path = path;
  e.before = before;
  e.after = after;
  if (pid > 0) { e.attributed = true; e.actor = trust::assessActor(pid); }
  return change::assess(e);
}

int main() {
  trust::setRpmDigestFn(&noRpm);
  const std::string sys = sysExe(), suid = setuidExe(), bash = bashExe();
  if (sys.empty() || suid.empty() || bash.empty()) {
    std::cerr << "skip: needs a root owned system program, a set-user-ID root program and bash\n";
    return 77;
  }
  const std::string base = "/tmp/oreon-attr-" + std::to_string(getpid());
  proc = base + "/proc";
  fs::create_directories(proc);
  trust::setProcRoot(proc);

  const std::string passwd0 =
    "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\nliveuser:x:1000:1000::/home/liveuser:/bin/bash\n";

  fakeProc(1, 0, 0, sys, sys);

  trust::setExtraTrustedOwnerForTests(getuid());
  const std::string target = base + "/sysimage";
  fs::create_directories(target + "/usr/sbin");
  fs::create_directories(target + "/etc");
  const auto dirPerm = fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec |
                       fs::perms::others_read | fs::perms::others_exec;
  for (const auto& d : {base, target, target + "/usr", target + "/usr/sbin", target + "/etc"})
    fs::permissions(d, dirPerm);
  fs::copy_file(sys, target + "/usr/sbin/useradd");
  fs::permissions(target + "/usr/sbin/useradd", dirPerm);
  fakeProc(7000, 1, 1000, bash, "bash");
  fakeProc(7001, 7000, 0, suid, suid + " centrio");
  fakeProc(7002, 7001, 0, bash, "python3 " + sys);
  fakeProc(7003, 7002, 0, sys, "chroot /mnt/sysimage useradd oreon");
  fakeProc(7004, 7003, 0, target + "/usr/sbin/useradd", "useradd -m oreon", target);

  auto useradd = trust::assessActor(7004);
  check(useradd.trust == ActorTrust::Trusted, "chrooted useradd under the installer is trusted: " + useradd.summary());
  {
    const std::string after = passwd0 + "oreon:x:1001:1001::/home/oreon:/bin/bash\n";
    auto v = judge(target + "/etc/passwd", passwd0, after, 7004);
    check(!v.alert, "useradd in the chroot target: no alert");
    v = judge("/etc/passwd", passwd0, after, 7004);
    check(!v.alert, "useradd changing the live host passwd: no alert");
  }
  {
    trust::noteProcess(7004);
    fs::remove_all(proc + "/7004");
    auto gone = trust::assessActor(7004);
    check(gone.trust == ActorTrust::Trusted, "exited writer judged from its exec snapshot");
    trust::forgetProcessesForTests();
    check(trust::assessActor(7004).trust == ActorTrust::Unattributed, "exited and never seen: unattributed");
    fakeProc(7004, 7003, 0, target + "/usr/sbin/useradd", "useradd -m oreon", target);
  }
  {
    WriteTracker wt;
    wt.record(target + "/etc/passwd+", 7004);
    WriteTracker::Write w;
    check(wt.lookup(target + "/etc/passwd", 5000, w) && w.actor.trust == ActorTrust::Trusted,
          "rename over passwd attributed to the writer of passwd+");
  }

  {
    auto v = judge(target + "/etc/passwd", passwd0, passwd0 + "admin2:x:0:0::/root:/bin/bash\n", 7004);
    check(v.alert && v.severity == Severity::Critical, "trusted writer adding a uid 0 account still alerts");
  }

  {
    const std::string evil = base + "/evil.sh";
    std::ofstream(evil) << "#!/bin/bash\necho toor:x:0:0::/root:/bin/bash >> /etc/passwd\n";
    fakeProc(7100, 1, 0, bash, "bash " + evil);
    auto a = trust::assessActor(7100);
    check(a.trust == ActorTrust::Untrusted, "root bash running a script from /tmp is untrusted");
    auto v = judge("/etc/passwd", passwd0, passwd0 + "toor:x:0:0::/root:/bin/bash\n", 7100);
    check(v.alert && v.severity == Severity::Critical, "untrusted script adding uid 0: alert");
    v = judge("/etc/passwd", passwd0, passwd0 + "eve:x:1500:1500::/home/eve:/bin/bash\n", 7100);
    check(v.alert && v.severity == Severity::High, "untrusted script adding any user: alert");
  }

  {
    fakeProc(7400, 1, 0, bash, "bash");
    check(trust::assessActor(7400).trust == ActorTrust::Untrusted, "interactive root shell is not trusted code");
    fakeProc(7401, 1, 0, bash, "bash -c id");
    check(trust::assessActor(7401).trust == ActorTrust::Untrusted, "inline shell code is not trusted");
    fakeProc(7402, 1, 0, bash, "bash " + sys);
    check(trust::assessActor(7402).trust == ActorTrust::Trusted, "shell running a system script is trusted");
  }

  const std::string sudo0 = "Defaults env_reset\nroot ALL=(ALL) ALL\n%wheel ALL=(ALL) ALL\n";
  {
    fakeProc(7200, 1, 1000, bash, "bash");
    auto v = judge("/etc/sudoers", sudo0, sudo0 + "eve ALL=(ALL) NOPASSWD: ALL\n", 7200);
    check(v.alert && v.severity >= Severity::High, "user shell adding NOPASSWD: alert");
    v = judge("/etc/sudoers", sudo0, sudo0 + "eve ALL=(ALL) NOPASSWD: ALL\n", 7402);
    check(v.alert, "NOPASSWD for a non-admin alerts even from trusted code");
    v = judge("/etc/sudoers", sudo0, sudo0 + "%wheel ALL=(ALL) NOPASSWD: ALL\n", 7402);
    check(!v.alert, "trusted change for an existing admin: no alert");
    v = judge("/etc/sudoers.d/90-bob", "", "bob ALL=(ALL) ALL\n", 0);
    check(v.alert && v.severity == Severity::Medium, "unattributed new admin grant: alert");
  }

  {
    fakeProc(7300, 1, 0, bash, "python3 " + sys + " install tpm2-tss");
    auto v = judge("/etc/passwd", passwd0, passwd0 + "tss:x:59:59:tss:/dev/null:/sbin/nologin\n", 7300);
    check(!v.alert, "dnf adding a system user: no alert");
  }

  {
    auto v = judge("/etc/passwd", passwd0, passwd0 + "newuser:x:1002:1002::/home/newuser:/bin/bash\n", 0);
    check(!v.alert, "unattributed benign new user: no alert");
    v = judge("/etc/passwd", passwd0, passwd0 + "x2:x:0:0::/:/bin/sh\n", 0);
    check(v.alert && v.severity == Severity::Critical, "unattributed uid 0 account: alert");
    v = judge("/etc/passwd", passwd0, passwd0 + "broken line\n", 0);
    check(v.alert && v.severity == Severity::Medium, "damaged passwd: alert");
    const std::string sh0 = "root:$6$abc:19000:0:99999:7:::\n";
    v = judge("/etc/shadow", sh0, "root::19000:0:99999:7:::\n", 7402);
    check(v.alert && v.severity == Severity::Critical, "empty root password alerts even from trusted code");
    v = judge("/etc/group", "root:x:0:\nwheel:x:10:\n", "root:x:0:eve\nwheel:x:10:\n", 0);
    check(v.alert, "user added to the root group: alert");
    v = judge("/etc/group", "root:x:0:\nwheel:x:10:\n", "root:x:0:\nwheel:x:10:oreon\n", 0);
    check(!v.alert, "user added to wheel by an unknown writer: no alert (normal install step)");
    v = judge("/root/.ssh/authorized_keys", "", "ssh-ed25519 AAAA attacker\n", 7402);
    check(v.alert && v.severity == Severity::Critical, "new root SSH key alerts even from trusted code");
    v = judge("/etc/ld.so.preload", "", "/tmp/x.so\n", 7402);
    check(v.alert, "new preload library alerts even from trusted code");
    change::Event pkg;
    pkg.path = "/etc/profile.d/x.sh";
    pkg.before = "a";
    pkg.after = "b";
    pkg.packageCopy = true;
    check(!change::assess(pkg).alert, "unattributed change that matches the rpm copy: no alert");
    pkg.packageCopy = false;
    check(change::assess(pkg).alert, "unattributed startup file change not from a package: alert");
  }

  {
    fs::permissions(target, fs::perms::others_write, fs::perm_options::add);
    check(trust::assessActor(7004).trust == ActorTrust::Untrusted, "world writable target is not trusted");
    fs::permissions(target, fs::perms::others_write, fs::perm_options::remove);
  }

  {
    auto v = judge("/home/u/Documents/.oreon-defense-keepsafe", "canary", "x", 7200);
    check(v.alert && v.killWriter && v.category == "ransomware", "user process changing a canary: alert and stop");
  }

  trust::setExtraTrustedOwnerForTests(0);
  trust::setProcRoot("");
  trust::setRpmDigestFn(nullptr);
  fs::remove_all(base);
  if (failures) return 1;
  std::cout << "ok\n";
  return 0;
}
