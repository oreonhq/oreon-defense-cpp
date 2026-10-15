#include "SystemTrust.hpp"
#include <oreon/Hash.hpp>
#include <oreon/Types.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <climits>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>

namespace fs = std::filesystem;
using namespace oreon::trust;

static int failures = 0;
static void check(bool c, const char* m) { if (!c) { std::cerr << "FAIL: " << m << "\n"; ++failures; } }

static std::string gDigest;
static std::string gRpmRoot;
static std::string fakeRpm(const std::string& root, const std::string&) { if (root != "/") gRpmRoot = root; return gDigest; }

static std::string pickSystemExe() {
  for (const char* c : {"/usr/lib/dracut/dracut-install", "/usr/bin/true", "/bin/true", "/usr/bin/ls"}) {
    char r[PATH_MAX];
    if (realpath(c, r) && classifySystemExe(r) != SystemExe::No) return r;
  }
  return {};
}

static void fakeProc(const std::string& root, int pid, int ppid, int uid, const std::string& comm,
                     const std::string& exe, const std::string& cmdline) {
  const std::string d = root + "/" + std::to_string(pid);
  fs::create_directories(d);
  std::ofstream(d + "/status") << "Name:\t" << comm << "\nPPid:\t" << ppid << "\nUid:\t" << uid
                               << "\t" << uid << "\t" << uid << "\t" << uid << "\n";
  std::ofstream(d + "/comm") << comm << "\n";
  std::ofstream c(d + "/cmdline");
  for (char ch : cmdline) c << (ch == ' ' ? '\0' : ch);
  c << '\0';
  fs::remove(d + "/exe");
  fs::create_symlink(exe, d + "/exe");
}

int main() {
  setRpmDigestFn(&fakeRpm);
  gDigest.clear();
  const std::string sys = pickSystemExe();
  if (sys.empty()) { std::cerr << "skip: no root owned system program\n"; return 77; }

  const std::string base = "/tmp/oreon-proctrust-" + std::to_string(getpid());
  const std::string procRoot = base + "/proc";
  fs::create_directories(procRoot);
  setProcRoot(procRoot);

  fakeProc(procRoot, 1, 0, 0, "systemd", sys, sys);
  fakeProc(procRoot, 4242, 1, 0, "dracut-install", sys,
           "/usr/lib/dracut/dracut-install -D /run/initramfs/live -a mkfifo socat sh -i");
  ActorVerdict pt = assessActor(4242);
  check(pt.root, "root");
  check(pt.exe == SystemExe::RootPath, "live media system path trusted without rpm");
  check(decideProcess(pt, false, true) == ProcessAction::Ignore, "dracut-install cmdline hit ignored");
  check(decideProcess(pt, false, false) == ProcessAction::Ignore, "dracut-install soft hit ignored");

  check(decideProcess(pt, true, true) == ProcessAction::AlertOnly, "file match on root system tool not killed");
  check(std::string(processActionName(decideProcess(pt, false, true))) == "ignore", "verdict name for log");
  check(std::string(systemExeName(pt.exe)) == "root-system-path", "trust name for log");
  check(pt.found && pt.uid == 0 && pt.ppid == 1, "log fields read from proc");
  {
    struct stat rs{};
    if (stat("/usr/lib/dracut/dracut-install", &rs) == 0) {
      check(classifySystemExe("/usr/lib/dracut/dracut-install") != SystemExe::No, "real dracut-install path trusted");
    }
  }

  {
    struct Engine { const char* name; bool exeBad; bool wantKill; };
    const Engine engines[] = {
      {"cmdline heuristic (mkfifo, socat, sh -i)", false, true},
      {"process rule name or cmdline match", false, true},
      {"ClamAV signature on the binary", true, true},
      {"file rule on the binary", true, true},
      {"exec protection", true, true},
      {"guard (persistence, privilege, ransomware)", true, true},
    };
    for (const auto& e : engines) {
      const auto a = decideProcess(pt, e.exeBad, e.wantKill);
      if (a == ProcessAction::AlertAndKill) { std::cerr << "FAIL: kill via " << e.name << "\n"; ++failures; }
    }
    check(!mayKill(pt), "killPid refuses root system tool (any engine, user request too)");
    check(protectedSystemProgram(sys), "exec of system program never denied");
    ActorVerdict rpmPt = pt; rpmPt.exe = SystemExe::RpmVerified;
    check(!mayKill(rpmPt), "killPid refuses rpm verified");
    ActorVerdict rpmShell = rpmPt; rpmShell.shellLike = true;
    check(!mayKill(rpmShell), "rpm verified shell not killed either");
    ActorVerdict rootShell = pt; rootShell.shellLike = true; rootShell.trust = ActorTrust::Untrusted;
    check(mayKill(rootShell), "unverified root shell can still be stopped");
    ActorVerdict user = pt; user.root = false; user.trust = ActorTrust::Untrusted;
    check(mayKill(user), "user process can be stopped");
    ActorVerdict none; none.root = true;
    check(mayKill(none), "untrusted root program can be stopped");
  }

  gDigest = oreon::sha256File(sys);
  check(classifySystemExe(sys) == SystemExe::RpmVerified, "rpm digest match");
  pt = assessActor(4242);
  check(decideProcess(pt, true, true) == ProcessAction::AlertOnly, "rpm verified root never killed");
  gDigest = std::string(64, 'a');
  check(classifySystemExe(sys) == SystemExe::RootPath, "rpm digest mismatch is not verified");
  gDigest.clear();

  const std::string fake = base + "/dracut-install";
  fs::copy_file(sys, fake);
  fakeProc(procRoot, 4343, 1, 0, "dracut-install", fake, "dracut-install mkfifo");
  pt = assessActor(4343);
  check(pt.exe == SystemExe::No, "name alone gives no trust");
  check(!protectedSystemProgram(fake), "fake copy in tmp can be denied");
  check(decideProcess(pt, false, true) == ProcessAction::AlertAndKill, "fake dracut-install still killed");

  fakeProc(procRoot, 4444, 1, 1000, "dracut-install", sys, "dracut-install mkfifo");
  pt = assessActor(4444);
  check(!pt.root && decideProcess(pt, false, true) == ProcessAction::AlertAndKill, "user process not trusted");

  ActorVerdict shell;
  shell.root = true; shell.exe = SystemExe::RootPath; shell.shellLike = true;
  check(decideProcess(shell, false, true) == ProcessAction::AlertAndKill, "root shell reverse shell killed");
  shell.exe = SystemExe::RpmVerified;
  check(decideProcess(shell, false, true) == ProcessAction::AlertOnly, "rpm verified root never killed, still alerted");

  check(classifySystemExe("/tmp/../tmp/x") == SystemExe::No, "tmp not trusted");

  setExtraTrustedOwnerForTests(getuid());
  {
    const std::string target = base + "/calamares-root-test";
    fs::create_directories(target + "/usr/lib/dracut");
    for (const auto& d : {base, target, target + "/usr", target + "/usr/lib", target + "/usr/lib/dracut"})
      fs::permissions(d, fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec |
                         fs::perms::others_read | fs::perms::others_exec);
    const std::string inChroot = target + "/usr/lib/dracut/dracut-install";
    fs::copy_file(sys, inChroot, fs::copy_options::overwrite_existing);
    fs::permissions(inChroot, fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec |
                              fs::perms::others_read | fs::perms::others_exec);
    fakeProc(procRoot, 5151, 5150, 0, "dracut-install", inChroot,
             "/usr/lib/dracut/dracut-install -D /var/tmp/dracut.XXXX/initramfs -a plymouthd mkfifo socat");
    fs::create_symlink(target, procRoot + "/5151/root");
    fakeProc(procRoot, 5150, 1, 0, "chroot", sys, sys);

    check(processRoot(5151) == target, "chroot root read from proc");
    check(trustedChrootRoot(target), "root owned target accepted");
    gDigest.clear();
    ActorVerdict c = assessActor(5151);
    check(c.chrootRoot == target, "chroot detected");
    check(c.exe == SystemExe::RootPath && c.trust == ActorTrust::Trusted, "chrooted dracut-install trusted by path inside target");
    check(gRpmRoot == procRoot + "/5151/root", "rpm asked with --root of the target (through /proc/<pid>/root), not the live host");
    check(decideProcess(c, false, true) == ProcessAction::Ignore, "chroot cmdline hit ignored");
    check(decideProcess(c, true, true) != ProcessAction::AlertAndKill, "chroot file hit never killed");
    check(!mayKill(c), "killPid refuses chrooted system tool");
    gDigest = oreon::sha256File(inChroot);
    check(classifyChrootExe(target, "/usr/lib/dracut/dracut-install") == SystemExe::RpmVerified, "target rpm db digest");
    gDigest.clear();

    fs::permissions(target, fs::perms::others_write, fs::perm_options::add);
    ActorVerdict bad = assessActor(5151);
    check(bad.exe == SystemExe::No, "world writable chroot not trusted");
    check(decideProcess(bad, false, true) == ProcessAction::AlertAndKill, "untrusted chroot still killed");
    fs::permissions(target, fs::perms::others_write, fs::perm_options::remove);

    fs::permissions(target + "/usr", fs::perms::group_write, fs::perm_options::add);
    check(classifyChrootExe(target, "/usr/lib/dracut/dracut-install") == SystemExe::No, "writable target usr not trusted");
    fs::permissions(target + "/usr", fs::perms::group_write, fs::perm_options::remove);

    check(classifyChrootExe(target, "/usr/../tmp/x") == SystemExe::No, "dotdot rejected");
    check(classifyChrootExe(target, "/tmp/dracut-install") == SystemExe::No, "non system folder in target rejected");
  }
  setExtraTrustedOwnerForTests(0);

  check(firstInWindow("/usr/lib/dracut/dracut-install|process-watch", 1000, 60), "first alert");
  check(!firstInWindow("/usr/lib/dracut/dracut-install|process-watch", 1010, 60), "repeat suppressed");
  check(firstInWindow("/usr/lib/dracut/dracut-install|process-watch", 1100, 60), "after window alerts again");
  check(firstInWindow("/usr/bin/other|process-watch", 1010, 60), "other exe not suppressed");

  setProcRoot("");
  setRpmDigestFn(nullptr);
  fs::remove_all(base);
  if (failures) return 1;
  std::cout << "ok\n";
  return 0;
}
