#include "SystemTrust.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <fstream>
#include <mutex>
#include <thread>
#include <regex>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <climits>
#include <cstdlib>
#include <map>
#include <sstream>
#include <unordered_map>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <oreon/Hash.hpp>

extern char** environ;

namespace oreon {
namespace trust {

namespace {

std::mutex gRootMu;
std::string gProcRoot = "/proc";

std::string procRoot() {
  std::lock_guard<std::mutex> lock(gRootMu);
  return gProcRoot;
}

bool startsWith(const std::string& s, const std::string& p) {
  return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

bool endsWith(const std::string& s, const std::string& p) {
  return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}

std::string baseName(const std::string& p) {
  auto i = p.find_last_of('/');
  return i == std::string::npos ? p : p.substr(i + 1);
}

std::string dirName(const std::string& p) {
  auto i = p.find_last_of('/');
  if (i == std::string::npos) return ".";
  if (i == 0) return "/";
  return p.substr(0, i);
}

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
  return s;
}

std::string readSmall(const std::string& path, size_t max = 65536) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return {};
  std::string s(max, '\0');
  in.read(&s[0], static_cast<std::streamsize>(max));
  s.resize(static_cast<size_t>(in.gcount()));
  return s;
}

uid_t gExtraOwner = 0;

bool rootOwnedStable(const struct stat& st) {
  return (st.st_uid == 0 || st.st_uid == gExtraOwner) && !(st.st_mode & (S_IWGRP | S_IWOTH));
}

bool systemProgramPath(const std::string& p) {
  for (const char* d : {"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/"})
    if (startsWith(p, d)) return true;
  return false;
}

std::string stagingRoot(const std::string& path) {
  static const char* tmpPrefixes[] = {
    "dracut.", "dracut-", "kernel-", "kernel-install.", "mkinitramfs", "initramfs.",
    "akmods", "akmodsbuild", "rpm-tmp.", "lorax.", "anaconda", "calamares",
  };
  for (const char* tmp : {"/var/tmp/", "/tmp/"}) {
    if (!startsWith(path, tmp)) continue;
    std::string rest = path.substr(strlen(tmp));
    auto slash = rest.find('/');
    std::string first = rest.substr(0, slash);
    for (const char* pre : tmpPrefixes)
      if (startsWith(first, pre)) return std::string(tmp) + first;
  }
  static const char* dirs[] = {
    "/var/cache/dnf", "/var/cache/libdnf5", "/var/cache/yum", "/var/cache/PackageKit",
    "/var/cache/akmods", "/var/lib/dnf", "/var/lib/rpm", "/var/lib/PackageKit",
    "/usr/lib/sysimage/rpm", "/usr/lib/sysimage/libdnf5", "/var/lib/rpm-state",
  };
  for (const char* d : dirs) {
    std::string dir = d;
    if (startsWith(path, dir + "/")) return dir;
  }
  return {};
}

bool rpmTempName(const std::string& base) {
  auto semi = base.rfind(';');
  if (semi == std::string::npos || base.size() - semi - 1 != 8) return false;
  return std::all_of(base.begin() + static_cast<long>(semi) + 1, base.end(),
                     [](unsigned char c) { return std::isxdigit(c); });
}

bool sameContent(int fd, const std::string& ref, off_t size) {
  int rfd = open(ref.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (rfd < 0) return false;
  bool same = true;
  char a[65536], b[65536];
  off_t off = 0;
  while (off < size) {
    size_t want = static_cast<size_t>(std::min<off_t>(sizeof(a), size - off));
    ssize_t na = pread(fd, a, want, off);
    ssize_t nb = pread(rfd, b, want, off);
    if (na <= 0 || na != nb || memcmp(a, b, static_cast<size_t>(na)) != 0) {
      same = false;
      break;
    }
    off += na;
  }
  close(rfd);
  return same;
}

std::string gShownReal, gShownAs;
std::string shownPath(const std::string& p) {
  if (!gShownReal.empty() && startsWith(p, gShownReal)) return gShownAs + p.substr(gShownReal.size());
  return p;
}

struct ProcInfo {
  int pid{0};
  int ppid{0};
  long euid{-1};
  std::string comm;
  std::string exe;
  std::vector<std::string> argv;
  struct stat exeSt{};
  bool exeStat{false};
  bool exeDeleted{false};
  std::string root{"/"};
  std::string view;
  std::string hostExe;
  std::string cwd;
  bool innerOk{true};
  bool raced{false};
  unsigned long long start{0};
  int linkTrust{-1};
  std::string linkWhy;
};

std::string readLinkStr(const std::string& p) {
  char buf[PATH_MAX];
  ssize_t n = readlink(p.c_str(), buf, sizeof(buf) - 1);
  if (n <= 0) return {};
  return shownPath(std::string(buf, static_cast<size_t>(n)));
}

std::string baseNameOf(const std::string& p) {
  auto s = p.find_last_of('/');
  return s == std::string::npos ? p : p.substr(s + 1);
}

bool sameFile(const struct stat& a, const struct stat& b) {
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

bool readProcOnce(int pid, ProcInfo& pi) {
  const std::string base = procRoot() + "/" + std::to_string(pid);
  std::string status = readSmall(base + "/status", 8192);
  if (status.empty()) return false;
  pi = ProcInfo{};
  pi.pid = pid;
  pi.view = base + "/root";
  auto field = [&](const char* key) -> std::string {
    auto pos = status.find(std::string("\n") + key);
    if (pos == std::string::npos) {
      if (startsWith(status, key)) pos = 0;
      else return {};
    } else {
      pos += 1;
    }
    pos += strlen(key);
    auto end = status.find('\n', pos);
    return status.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
  };
  pi.ppid = atoi(field("PPid:").c_str());
  {
    const std::string st = readSmall(base + "/stat", 4096);
    auto rp = st.rfind(')');
    if (rp != std::string::npos) {
      std::istringstream in(st.substr(rp + 2));
      std::string tok;
      for (int f = 3; f <= 22 && (in >> tok); ++f)
        if (f == 22) pi.start = strtoull(tok.c_str(), nullptr, 10);
    }
  }
  {
    std::string uid = field("Uid:");
    long r = -1, e = -1;
    if (sscanf(uid.c_str(), "%ld %ld", &r, &e) == 2) pi.euid = e;
  }
  pi.comm = readSmall(base + "/comm", 256);
  while (!pi.comm.empty() && (pi.comm.back() == '\n' || pi.comm.back() == '\r')) pi.comm.pop_back();
  pi.exe = readLinkStr(base + "/exe");
  {
    const std::string del = " (deleted)";
    if (endsWith(pi.exe, del)) {
      pi.exe.resize(pi.exe.size() - del.size());
      pi.exeDeleted = true;
    }
  }
  {
    int fd = open((base + "/exe").c_str(), O_PATH | O_CLOEXEC);
    if (fd >= 0) {
      pi.exeStat = fstat(fd, &pi.exeSt) == 0;
      close(fd);
    }
  }
  pi.hostExe = pi.exe;
  {
    std::string r = readLinkStr(base + "/root");
    while (r.size() > 1 && r.back() == '/') r.pop_back();
    if (!r.empty() && r[0] == '/' && r != "/") pi.root = r;
  }
  if (pi.root != "/" && !pi.exe.empty()) {
    pi.innerOk = false;
    std::vector<std::string> cands;
    if (startsWith(pi.exe, pi.root + "/")) cands.push_back(pi.exe.substr(pi.root.size()));
    for (size_t p = pi.exe.find('/', 1); p != std::string::npos; p = pi.exe.find('/', p + 1))
      cands.push_back(pi.exe.substr(p));
    for (const auto& c : cands) {
      struct stat cs{};
      if (lstat((pi.view + c).c_str(), &cs) == 0 && S_ISREG(cs.st_mode) &&
          (!pi.exeStat || sameFile(cs, pi.exeSt))) {
        pi.exe = c;
        pi.innerOk = pi.exeStat;
        break;
      }
    }
  }
  {
    std::string c = readLinkStr(base + "/cwd");
    if (pi.root != "/" && startsWith(c, pi.root + "/")) c = c.substr(pi.root.size());
    else if (pi.root != "/" && c == pi.root) c = "/";
    pi.cwd = c;
  }
  std::string cmd = readSmall(base + "/cmdline", 8192);
  size_t start = 0;
  for (size_t i = 0; i <= cmd.size(); ++i) {
    if (i == cmd.size() || cmd[i] == '\0') {
      if (i > start) pi.argv.push_back(cmd.substr(start, i - start));
      start = i + 1;
    }
  }
  return true;
}

bool procConsistent(const ProcInfo& pi) {
  if (pi.exe.empty() || pi.comm.empty()) return true;
  if (baseNameOf(pi.exe).compare(0, 15, pi.comm, 0, 15) == 0) return true;
  for (size_t i = 1; i < pi.argv.size() && i < 4; ++i)
    if (baseNameOf(pi.argv[i]).compare(0, 15, pi.comm, 0, 15) == 0) return true;
  return false;
}

bool readProc(int pid, ProcInfo& pi) {
  for (int attempt = 0; attempt < 6; ++attempt) {
    if (attempt) std::this_thread::sleep_for(std::chrono::milliseconds(2));
    if (!readProcOnce(pid, pi)) return false;
    if (procConsistent(pi)) return true;
  }
  pi.raced = true;
  return true;
}


bool interpreter(const std::string& base) {
  static const char* names[] = {"sh", "bash", "dash", "zsh", "ksh", "perl", "ruby", "lua", "node"};
  for (const char* n : names)
    if (base == n) return true;
  return startsWith(base, "python") || startsWith(base, "perl5") || startsWith(base, "lua5");
}



bool chrootRootOk(const std::string& root);

}

void setProcRoot(const std::string& root) {
  std::lock_guard<std::mutex> lock(gRootMu);
  gProcRoot = root.empty() ? "/proc" : root;
}

bool systemStagingPath(const std::string& path) {
  std::string root = stagingRoot(path);
  if (!root.empty()) {
    struct stat st{};
    if (lstat(root.c_str(), &st) == 0 && S_ISDIR(st.st_mode) && rootOwnedStable(st)) return true;
    return false;
  }
  if (rpmTempName(baseName(path))) {
    struct stat st{};
    std::string dir = dirName(path);
    if (lstat(dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode) && rootOwnedStable(st)) return true;
  }
  return false;
}

bool userWritableArea(const std::string& path) {
  for (const char* d : {"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/home/", "/var/home/", "/root/"})
    if (startsWith(path, d)) return true;
  return path.find("/Downloads/") != std::string::npos || path.find("/Desktop/") != std::string::npos;
}

bool droppableByUser(const std::string& path, const struct stat& st) {
  if (st.st_uid != 0) return true;
  struct stat dst{};
  if (stat(dirName(path).c_str(), &dst) != 0) return true;
  if (dst.st_uid != 0) return true;
  return (dst.st_mode & (S_IWGRP | S_IWOTH)) != 0;
}

bool copyOfSystemFile(int fd, const std::string& path, const struct stat& st) {
  if (fd < 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) return false;
  if (st.st_size > 256LL * 1024 * 1024) return false;
  std::vector<std::string> refs;
  for (const char* anchor : {"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/"}) {
    auto pos = path.rfind(anchor);
    if (pos == std::string::npos || pos == 0) continue;
    std::string tail = path.substr(pos);
    refs.push_back(tail);
    if (!startsWith(tail, "/usr/")) refs.push_back("/usr" + tail);
  }
  std::string base = baseName(path);
  if (!base.empty() && base != "." && base != "..") {
    for (const char* d : {"/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib64/", "/usr/lib/",
                          "/usr/lib/x86_64-linux-gnu/", "/usr/lib/aarch64-linux-gnu/",
                          "/usr/lib/systemd/", "/usr/lib/systemd/system-generators/"})
      refs.push_back(std::string(d) + base);
  }
  for (const auto& r : refs) {
    struct stat rst{};
    if (stat(r.c_str(), &rst) != 0 || !S_ISREG(rst.st_mode)) continue;
    if (rst.st_dev == st.st_dev && rst.st_ino == st.st_ino) return true;
    if (rst.st_size != st.st_size || !rootOwnedStable(rst)) continue;
    char real[PATH_MAX];
    if (!realpath(r.c_str(), real) || !startsWith(real, "/usr/")) continue;
    if (sameContent(fd, real, st.st_size)) return true;
  }
  return false;
}


bool packageTransactionActive() {
  using clock = std::chrono::steady_clock;
  static std::mutex mu;
  static clock::time_point last{};
  static bool cached = false;
  static std::string cachedRoot;
  std::lock_guard<std::mutex> lock(mu);
  auto now = clock::now();
  std::string root = procRoot();
  if (root == cachedRoot && last.time_since_epoch().count() != 0 && now - last < std::chrono::seconds(2))
    return cached;
  bool active = false;
  if (root == "/proc") {
    for (const char* lf : {"/var/lib/rpm/.rpm.lock", "/usr/lib/sysimage/rpm/.rpm.lock"}) {
      int fd = open(lf, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
      if (fd < 0) continue;
      struct flock fl{};
      fl.l_type = F_RDLCK;
      fl.l_whence = SEEK_SET;
      if (fcntl(fd, F_GETLK, &fl) == 0 && fl.l_type != F_UNLCK) active = true;
      close(fd);
      if (active) break;
    }
  }
  cached = active;
  cachedRoot = root;
  last = now;
  return active;
}

bool isAutostartEntry(const std::string& path) {
  return endsWith(path, ".desktop") &&
         (path.find("/.config/autostart/") != std::string::npos ||
          startsWith(path, "/etc/xdg/autostart/"));
}

namespace {

std::vector<std::string> splitExec(const std::string& s) {
  std::vector<std::string> out;
  std::string cur;
  bool inQuote = false, have = false;
  for (size_t i = 0; i < s.size(); ++i) {
    char c = s[i];
    if (inQuote) {
      if (c == '\\' && i + 1 < s.size()) { cur.push_back(s[++i]); continue; }
      if (c == '"') { inQuote = false; continue; }
      cur.push_back(c);
    } else if (c == '"') {
      inQuote = true;
      have = true;
    } else if (c == ' ' || c == '\t') {
      if (have || !cur.empty()) out.push_back(cur);
      cur.clear();
      have = false;
    } else {
      cur.push_back(c);
    }
  }
  if (have || !cur.empty()) out.push_back(cur);
  out.erase(std::remove_if(out.begin(), out.end(),
                           [](const std::string& t) { return t.size() == 2 && t[0] == '%'; }),
            out.end());
  return out;
}

bool hiddenOrHomeRef(const std::string& t) {
  if (startsWith(t, "~") || t.find("$HOME") != std::string::npos ||
      t.find("${HOME}") != std::string::npos || t.find("$XDG_") != std::string::npos)
    return true;
  return t.find("/.") != std::string::npos && t.find("/./") == std::string::npos;
}

bool userPath(const std::string& t) {
  if (t.empty()) return false;
  if (hiddenOrHomeRef(t)) return true;
  return t[0] == '/' && userWritableArea(t);
}

bool rootOwnedProgram(const std::string& p) {
  struct stat st{};
  if (stat(p.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return false;
  char real[PATH_MAX];
  if (!realpath(p.c_str(), real)) return false;
  return rootOwnedStable(st) && systemProgramPath(real);
}

bool identicalToSystemCopy(const std::string& path, const std::string& content) {
  std::string base = baseName(path);
  for (const char* d : {"/etc/xdg/autostart/", "/usr/share/applications/", "/usr/share/autostart/"}) {
    std::string ref = std::string(d) + base;
    if (ref == path) continue;
    struct stat st{};
    if (stat(ref.c_str(), &st) != 0 || !S_ISREG(st.st_mode) || !rootOwnedStable(st)) continue;
    if (static_cast<size_t>(st.st_size) != content.size()) continue;
    if (readSmall(ref, content.size() + 1) == content) return true;
  }
  return false;
}

}

AutostartVerdict checkAutostart(const std::string& path, const std::string& content) {
  AutostartVerdict v;
  if (content.empty()) return v;
  std::string exec;
  bool inEntry = false, hidden = false;
  size_t pos = 0;
  while (pos < content.size()) {
    auto end = content.find('\n', pos);
    std::string line = content.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
    pos = end == std::string::npos ? content.size() : end + 1;
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
    if (line.empty() || line[0] == '#') continue;
    if (line[0] == '[') {
      inEntry = line == "[Desktop Entry]";
      continue;
    }
    if (!inEntry) continue;
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    std::string key = line.substr(0, eq);
    while (!key.empty() && key.back() == ' ') key.pop_back();
    std::string val = line.substr(eq + 1);
    while (!val.empty() && val.front() == ' ') val.erase(val.begin());
    if (key == "Exec") exec = val;
    else if (key == "Hidden") hidden = lower(val) == "true";
  }
  if (exec.empty() || hidden) return v;
  if (identicalToSystemCopy(path, content)) return v;

  static const std::regex tricks(
      R"((^|[\s;|&(/"'])(curl|wget|nc|ncat|socat|base64|xxd|openssl)(\s|$))"
      R"(|(^|[\s;|&(/"'])(ba|z|da|k|c|tc)?sh\s+(-[a-z]*\s+)*-[a-z]*c)"
      R"(|python[0-9.]*\s+(-[a-z]+\s+)*-[a-z]*c)"
      R"(|(perl|ruby|node)\s+(-[a-z]+\s+)*-[a-z]*e)"
      R"(|\|\s*(/usr)?(/bin/)?(ba|z|da|k)?sh\b)"
      R"(|/dev/(tcp|udp)/|\$\(|`|\beval\b|\bmkfifo\b)",
      std::regex::ECMAScript | std::regex::icase);
  if (std::regex_search(exec, tricks)) {
    v.suspicious = true;
    v.reason = "autostart command uses download, decode or shell tricks";
    return v;
  }

  auto toks = splitExec(exec);
  size_t i = 0;
  if (i < toks.size() && (toks[i] == "env" || toks[i] == "/usr/bin/env" || toks[i] == "/bin/env")) ++i;
  for (; i < toks.size(); ++i) {
    const std::string& t = toks[i];
    if (!t.empty() && t[0] == '-') continue;
    auto eq = t.find('=');
    if (eq == std::string::npos || t.find('/') < eq) break;
    std::string var = t.substr(0, eq);
    if ((var == "LD_PRELOAD" || var == "LD_AUDIT" ||
         (var == "LD_LIBRARY_PATH" && userPath(t.substr(eq + 1)))) && t.size() > eq + 1) {
      v.suspicious = true;
      v.reason = "autostart command preloads a library (" + var + ")";
      return v;
    }
  }
  if (i >= toks.size()) return v;
  const std::string prog = toks[i];

  if (prog.find('/') != std::string::npos || hiddenOrHomeRef(prog)) {
    if (prog[0] != '/') {
      v.suspicious = true;
      v.reason = "autostart runs a relative or home path: " + prog;
      return v;
    }
    if (userPath(prog)) {
      v.suspicious = true;
      v.reason = "autostart runs a program from a user writable or hidden folder: " + prog;
      return v;
    }
    struct stat st{};
    if (stat(prog.c_str(), &st) == 0 && S_ISREG(st.st_mode) && !rootOwnedStable(st)) {
      v.suspicious = true;
      v.reason = "autostart runs a program that is not root owned: " + prog;
      return v;
    }
  } else {
    bool found = false;
    for (const char* d : {"/usr/local/bin/", "/usr/bin/", "/bin/", "/usr/local/sbin/", "/usr/sbin/", "/sbin/"}) {
      std::string cand = std::string(d) + prog;
      if (access(cand.c_str(), X_OK) == 0) {
        found = true;
        if (!rootOwnedProgram(cand)) {
          v.suspicious = true;
          v.reason = "autostart runs a program that is not root owned: " + cand;
          return v;
        }
        break;
      }
    }
    if (!found) {
      auto at = path.find("/.config/autostart/");
      if (at != std::string::npos) {
        std::string home = path.substr(0, at);
        for (const char* d : {"/.local/bin/", "/bin/"}) {
          std::string cand = home + d + prog;
          if (access(cand.c_str(), F_OK) == 0) {
            v.suspicious = true;
            v.reason = "autostart runs a program from the home folder: " + cand;
            return v;
          }
        }
      }
    }
  }

  if (interpreter(baseName(prog))) {
    for (size_t j = i + 1; j < toks.size(); ++j) {
      if (userPath(toks[j])) {
        v.suspicious = true;
        v.reason = "autostart runs a script from a user writable or hidden folder: " + toks[j];
        return v;
      }
    }
  }
  return v;
}

namespace {

RpmDigestFn gRpmFn = nullptr;

std::string realRpmDigest(const std::string& root, const std::string& path) {
  const char* rpmBin = nullptr;
  for (const char* c : {"/usr/bin/rpm", "/bin/rpm"})
    if (access(c, X_OK) == 0) { rpmBin = c; break; }
  if (!rpmBin) return {};
  int pfd[2];
  if (pipe2(pfd, O_CLOEXEC) != 0) return {};
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_adddup2(&fa, pfd[1], 1);
  posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
  std::string qf = "[%{FILENAMES}\t%{FILEDIGESTS}\n]";
  std::vector<std::string> args = {rpmBin};
  if (root != "/") { args.push_back("--root"); args.push_back(root); }
  for (const char* a : {"-qf", "--qf"}) args.push_back(a);
  args.push_back(qf);
  args.push_back("--");
  args.push_back(path);
  std::vector<char*> argv;
  for (auto& a : args) argv.push_back(a.data());
  argv.push_back(nullptr);
  pid_t child = -1;
  int rc = posix_spawn(&child, rpmBin, &fa, nullptr, argv.data(), environ);
  posix_spawn_file_actions_destroy(&fa);
  close(pfd[1]);
  if (rc != 0) { close(pfd[0]); return {}; }
  std::string out;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  char buf[8192];
  for (;;) {
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
    if (left <= 0) { kill(child, SIGKILL); break; }
    pollfd p{pfd[0], POLLIN, 0};
    int pr = poll(&p, 1, static_cast<int>(left));
    if (pr < 0 && errno == EINTR) continue;
    if (pr <= 0) { kill(child, SIGKILL); break; }
    ssize_t n = read(pfd[0], buf, sizeof(buf));
    if (n <= 0) break;
    if (out.size() < (8u << 20)) out.append(buf, static_cast<size_t>(n));
  }
  close(pfd[0]);
  int status = 0;
  while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return {};
  size_t start = 0;
  while (start < out.size()) {
    size_t end = out.find('\n', start);
    if (end == std::string::npos) end = out.size();
    const std::string line = out.substr(start, end - start);
    start = end + 1;
    auto tab = line.find('\t');
    if (tab == std::string::npos) continue;
    if (line.compare(0, tab, path) == 0 && tab == path.size()) {
      std::string d = lower(line.substr(tab + 1));
      return d.size() == 64 ? d : std::string();
    }
  }
  return {};
}

std::string rpmDigest(const std::string& root, const std::string& path) {
  return gRpmFn ? gRpmFn(root, path) : realRpmDigest(root, path);
}

bool rootChain(const std::string& path) {
  std::string d = dirName(path);
  for (int i = 0; i < 64; ++i) {
    struct stat st{};
    if (lstat(d.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) || !rootOwnedStable(st)) return false;
    if (d == "/" || d.empty()) return true;
    d = dirName(d);
  }
  return false;
}

bool chrootParentsOk(const std::string& root, std::string* why) {
  std::string d = dirName(root);
  for (int i = 0; i < 64 && !d.empty(); ++i) {
    struct stat st{};
    if (lstat(d.c_str(), &st) == 0) {
      if (st.st_uid != 0 && st.st_uid != gExtraOwner) {
        if (why) *why = "folder above the chroot is not root owned: " + d;
        return false;
      }
    }
    if (d == "/") return true;
    d = dirName(d);
  }
  return true;
}

bool chrootViewOk(const std::string& view, const std::string& root, std::string* why) {
  if (root.empty() || root[0] != '/' || root == "/") { if (why) *why = "no chroot root"; return false; }
  struct stat st{};
  if (stat(view.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) || !rootOwnedStable(st)) {
    if (why) *why = "chroot root is not root owned or is writable: " + root;
    return false;
  }
  struct stat us{};
  if (lstat((view + "/usr").c_str(), &us) != 0 || !S_ISDIR(us.st_mode) || !rootOwnedStable(us)) {
    if (why) *why = "chroot usr/ is not root owned or is writable: " + root + "/usr";
    return false;
  }
  return chrootParentsOk(root, why);
}

bool chrootRootOk(const std::string& root) { return chrootViewOk(root, root, nullptr); }

std::string resolveInRoot(const std::string& view, const std::string& path) {
  if (path.empty() || path[0] != '/') return {};
  std::vector<std::string> todo;
  auto pushParts = [&](const std::string& p) {
    std::vector<std::string> parts;
    size_t i = 0;
    while (i < p.size()) {
      size_t j = p.find('/', i);
      if (j == std::string::npos) j = p.size();
      if (j > i) parts.push_back(p.substr(i, j - i));
      i = j + 1;
    }
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) todo.push_back(*it);
  };
  pushParts(path);
  std::string cur;
  for (int hops = 0; !todo.empty();) {
    std::string part = todo.back();
    todo.pop_back();
    if (part == ".") continue;
    if (part == "..") { cur = cur.empty() ? cur : dirName(cur); if (cur == "/") cur.clear(); continue; }
    std::string next = cur + "/" + part;
    struct stat st{};
    if (lstat((view + next).c_str(), &st) != 0) return {};
    if (S_ISLNK(st.st_mode)) {
      if (++hops > 40) return {};
      char buf[PATH_MAX];
      ssize_t n = readlink((view + next).c_str(), buf, sizeof(buf) - 1);
      if (n <= 0) return {};
      std::string t(buf, static_cast<size_t>(n));
      if (t[0] == '/') cur.clear();
      pushParts(t);
      continue;
    }
    cur = next;
  }
  return cur.empty() ? std::string("/") : cur;
}

SystemExe classifyInView(const std::string& view, const std::string& root, const std::string& inner,
                         std::string* why) {
  if (!chrootViewOk(view, root, why)) return SystemExe::No;
  if (inner.empty() || inner[0] != '/' || inner.find("/../") != std::string::npos) {
    if (why) *why = "bad inner path " + inner;
    return SystemExe::No;
  }
  if (!systemProgramPath(inner)) { if (why) *why = "not in a system folder: " + inner; return SystemExe::No; }
  const std::string at = view + inner;
  struct stat st{};
  if (lstat(at.c_str(), &st) != 0 || !S_ISREG(st.st_mode) || !rootOwnedStable(st)) {
    if (why) *why = "not a root owned, locked file: " + root + inner;
    return SystemExe::No;
  }
  for (std::string d = dirName(inner); ; d = dirName(d)) {
    struct stat ds{};
    const std::string dp = d == "/" ? view : view + d;
    if (stat(dp.c_str(), &ds) != 0 || !S_ISDIR(ds.st_mode) || !rootOwnedStable(ds)) {
      if (why) *why = "folder not root owned or writable: " + root + d;
      return SystemExe::No;
    }
    if (d == "/" || d.empty()) break;
  }
  struct stat rs{};
  stat(view.c_str(), &rs);
  static std::mutex mu;
  static std::map<std::string, SystemExe> cache;
  const std::string key = std::to_string(rs.st_dev) + ":" + std::to_string(rs.st_ino) + "|" + inner + "|" +
                          std::to_string(st.st_dev) + ":" + std::to_string(st.st_ino) + ":" +
                          std::to_string(st.st_mtim.tv_sec) + ":" + std::to_string(st.st_size);
  if (!gRpmFn) {
    std::lock_guard<std::mutex> lock(mu);
    auto it = cache.find(key);
    if (it != cache.end()) return it->second;
  }
  SystemExe v = SystemExe::RootPath;
  const std::string want = rpmDigest(view, inner);
  if (!want.empty() && lower(sha256File(at)) == want) v = SystemExe::RpmVerified;
  if (!gRpmFn) {
    std::lock_guard<std::mutex> lock(mu);
    if (cache.size() > 4096) cache.clear();
    cache[key] = v;
  }
  return v;
}

bool shellLikeName(const std::string& base) {
  if (interpreter(base)) return true;
  static const char* relays[] = {"nc", "ncat", "netcat", "socat", "telnet", "busybox", "php",
                                 "tclsh", "expect", "awk", "gawk", "openssl", "env", "xargs"};
  for (const char* r : relays)
    if (base == r) return true;
  return false;
}

}

void setRpmDigestFn(RpmDigestFn fn) { gRpmFn = fn; }

bool rpmFileDigestMatches(const std::string& root, const std::string& path) {
  const std::string want = rpmDigest(root, path);
  if (want.empty()) return false;
  const std::string host = root == "/" ? path : root + path;
  return lower(sha256File(host)) == want;
}
void setExtraTrustedOwnerForTests(uid_t uid) { gExtraOwner = uid; }

bool trustedChrootRoot(const std::string& root) { return chrootRootOk(root); }

std::string processRoot(pid_t pid) {
  std::string r = readLinkStr(procRoot() + "/" + std::to_string(pid) + "/root");
  while (r.size() > 1 && r.back() == '/') r.pop_back();
  return (r.empty() || r[0] != '/') ? std::string("/") : r;
}

void setShownPathForTests(const std::string& real, const std::string& shown) {
  gShownReal = real;
  gShownAs = shown;
}

ExeView exeView(pid_t pid) {
  ExeView v;
  ProcInfo pi;
  if (!readProc(static_cast<int>(pid), pi)) return v;
  v.ok = !pi.exe.empty();
  v.root = pi.root;
  v.inner = pi.exe;
  v.host = pi.hostExe;
  v.comm = pi.comm;
  v.raced = pi.raced;
  return v;
}

bool firstInWindow(const std::string& key, int64_t nowSec, int windowSec) {
  static std::mutex mu;
  static std::map<std::string, int64_t> seen;
  std::lock_guard<std::mutex> lock(mu);
  if (seen.size() > 2048) {
    for (auto it = seen.begin(); it != seen.end();)
      it = (nowSec - it->second > windowSec) ? seen.erase(it) : std::next(it);
  }
  auto it = seen.find(key);
  if (it != seen.end() && nowSec - it->second <= windowSec) return false;
  seen[key] = nowSec;
  return true;
}

SystemExe classifyChrootExe(const std::string& root, const std::string& inner) {
  return classifyInView(root, root, inner, nullptr);
}

SystemExe classifySystemExe(const std::string& path) {
  if (path.empty() || path[0] != '/') return SystemExe::No;
  char real[PATH_MAX];
  if (!realpath(path.c_str(), real)) return SystemExe::No;
  const std::string rp = real;
  if (!systemProgramPath(rp) || userWritableArea(rp) || systemStagingPath(rp)) return SystemExe::No;
  struct stat st{};
  if (lstat(rp.c_str(), &st) != 0 || !S_ISREG(st.st_mode) || !rootOwnedStable(st)) return SystemExe::No;
  if (!rootChain(rp)) return SystemExe::No;

  static std::mutex mu;
  static std::map<std::string, SystemExe> cache;
  const std::string key = rp + "|" + std::to_string(st.st_dev) + ":" + std::to_string(st.st_ino) +
                          ":" + std::to_string(st.st_mtim.tv_sec) + ":" + std::to_string(st.st_size);
  if (!gRpmFn) {
    std::lock_guard<std::mutex> lock(mu);
    auto it = cache.find(key);
    if (it != cache.end()) return it->second;
  }
  SystemExe v = SystemExe::RootPath;
  const std::string want = rpmDigest("/", rp);
  if (!want.empty() && lower(sha256File(rp)) == want) v = SystemExe::RpmVerified;
  if (!gRpmFn) {
    std::lock_guard<std::mutex> lock(mu);
    if (cache.size() > 4096) cache.clear();
    cache[key] = v;
  }
  return v;
}

const char* systemExeName(SystemExe e) {
  switch (e) {
  case SystemExe::RpmVerified: return "rpm-verified";
  case SystemExe::RootPath: return "root-system-path";
  default: return "untrusted";
  }
}

const char* processActionName(ProcessAction a) {
  switch (a) {
  case ProcessAction::Ignore: return "ignore";
  case ProcessAction::AlertOnly: return "alert";
  default: return "alert+kill";
  }
}



bool protectedSystemProgram(const std::string& path) {
  char real[PATH_MAX];
  if (!realpath(path.c_str(), real)) return false;
  if (shellLikeName(baseName(real))) return false;
  return classifySystemExe(real) != SystemExe::No;
}



namespace {

struct Snap { ProcInfo pi; int64_t at{0}; };
std::mutex gSnapMu;
std::unordered_map<int, Snap> gSnaps;

int64_t monoSec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::steady_clock::now().time_since_epoch()).count();
}

void storeSnap(const ProcInfo& pi) {
  std::lock_guard<std::mutex> lock(gSnapMu);
  if (gSnaps.size() > 8192) {
    const int64_t now = monoSec();
    for (auto it = gSnaps.begin(); it != gSnaps.end();)
      it = (now - it->second.at > 300) ? gSnaps.erase(it) : std::next(it);
  }
  gSnaps[pi.pid] = Snap{pi, monoSec()};
}

bool readActor(int pid, ProcInfo& pi, bool& fromSnap) {
  fromSnap = false;
  if (readProc(pid, pi)) {
    std::lock_guard<std::mutex> lock(gSnapMu);
    auto it = gSnaps.find(pid);
    if (it != gSnaps.end() && it->second.pi.start != 0 && pi.start != 0 && it->second.pi.start != pi.start)
      gSnaps.erase(it);
    return true;
  }
  std::lock_guard<std::mutex> lock(gSnapMu);
  auto it = gSnaps.find(pid);
  if (it == gSnaps.end() || monoSec() - it->second.at > 300) return false;
  pi = it->second.pi;
  fromSnap = true;
  return true;
}

SystemExe judgeFile(const ProcInfo& pi, const std::string& path, std::string* why) {
  if (pi.root == "/") return classifySystemExe(path);
  const std::string inner = resolveInRoot(pi.view, path);
  if (inner.empty()) { if (why) *why = "cannot reach " + path + " inside the chroot"; return SystemExe::No; }
  return classifyInView(pi.view, pi.root, inner, why);
}

SystemExe judgeModule(const ProcInfo& pi, const std::string& mod, std::string& found) {
  if (mod.empty() || mod.find('/') != std::string::npos || mod.find("..") != std::string::npos) return SystemExe::No;
  std::string rel = mod;
  for (char& c : rel) if (c == '.') c = '/';
  std::vector<std::string> dirs;
  const std::string view = pi.root == "/" ? std::string() : pi.view;
  for (const char* lib : {"/usr/lib64", "/usr/lib"}) {
    DIR* d = opendir((view + lib).c_str());
    if (!d) continue;
    while (dirent* e = readdir(d)) {
      std::string n = e->d_name;
      if (!startsWith(n, "python3")) continue;
      dirs.push_back(std::string(lib) + "/" + n + "/site-packages");
      dirs.push_back(std::string(lib) + "/" + n);
    }
    closedir(d);
  }
  if (!pi.cwd.empty() && pi.cwd[0] == '/') dirs.push_back(pi.cwd);
  for (const auto& d : dirs) {
    for (const std::string& c : {d + "/" + rel + ".py", d + "/" + rel + "/__main__.py"}) {
      struct stat st{};
      if (lstat((view + c).c_str(), &st) != 0) continue;
      std::string w;
      SystemExe v = judgeFile(pi, c, &w);
      if (v != SystemExe::No) { found = c; return v; }
      found = c;
      return SystemExe::No;
    }
  }
  return SystemExe::No;
}

SystemExe judgeLinkNow(const ProcInfo& pi, std::string& why) {
  if (pi.exeDeleted) { why = "program file was replaced or deleted"; return SystemExe::No; }
  if (pi.exe.empty()) { why = "no program file"; return SystemExe::No; }
  const bool chrooted = pi.root != "/";
  SystemExe bin;
  if (chrooted) {
    if (!pi.innerOk) { why = "program not found inside its chroot " + pi.root + ": " + pi.hostExe; return SystemExe::No; }
    std::string w;
    bin = classifyInView(pi.view, pi.root, pi.exe, &w);
    if (bin == SystemExe::No) { why = "chroot program not trusted (" + w + ")"; return SystemExe::No; }
  } else {
    bin = classifySystemExe(pi.exe);
  }
  if (bin == SystemExe::No) {
    why = "program is not a locked down system file: " + pi.hostExe;
    return SystemExe::No;
  }
  const std::string where = chrooted ? pi.root + ":" + pi.exe : pi.exe;
  const std::string b = baseName(pi.exe);
  if (!interpreter(b)) { why = std::string("system program ") + where + " (" + systemExeName(bin) + ")"; return bin; }
  const bool py = startsWith(b, "python");
  const bool sh = b == "sh" || b == "bash" || b == "dash" || b == "zsh" || b == "ksh";
  for (size_t i = 1; i < pi.argv.size() && i < 6; ++i) {
    const std::string& a = pi.argv[i];
    if (a.empty()) continue;
    if (a == "--") continue;
    if (a[0] == '-' || a[0] == '+') {
      const bool cluster = a.size() >= 2 && a[1] != '-';
      if (sh && cluster && (a.find('c', 1) != std::string::npos || a.find('s', 1) != std::string::npos ||
                            a.find('i', 1) != std::string::npos)) {
        why = "shell runs inline, stdin or interactive code";
        return SystemExe::No;
      }
      if (sh && (a == "-o" || a == "+o" || a == "-O" || a == "+O")) { ++i; continue; }
      if (py && cluster && a.find('c', 1) != std::string::npos) { why = "python runs inline code"; return SystemExe::No; }
      if (py && cluster && a.find('i', 1) != std::string::npos) { why = "python runs interactively"; return SystemExe::No; }
      if (py && a == "-m") {
        if (i + 1 >= pi.argv.size()) break;
        std::string file;
        SystemExe m = judgeModule(pi, pi.argv[i + 1], file);
        if (m == SystemExe::No) {
          why = "python module " + pi.argv[i + 1] + " is not a locked down system file" +
                (file.empty() ? std::string() : ": " + file);
          return SystemExe::No;
        }
        why = "python runs system module " + pi.argv[i + 1] + " (" + file + ")";
        return std::min(bin, m);
      }
      if (py && (a == "-X" || a == "-W")) { ++i; continue; }
      if (!sh && !py && cluster && (a.find('e', 1) != std::string::npos || a.find('E', 1) != std::string::npos)) {
        why = "interpreter runs inline code";
        return SystemExe::No;
      }
      continue;
    }
    std::string target = a;
    if (a[0] != '/') {
      if (pi.cwd.empty() || a.find("..") != std::string::npos) { why = "interpreter runs a relative script: " + a; return SystemExe::No; }
      target = (pi.cwd == "/" ? std::string() : pi.cwd) + "/" + a;
    }
    std::string w;
    SystemExe sc = judgeFile(pi, target, &w);
    if (sc == SystemExe::No) {
      why = "interpreter runs an unverified script: " + target + (w.empty() ? std::string() : " (" + w + ")");
      return SystemExe::No;
    }
    why = "interpreter runs system script " + target;
    return std::min(bin, sc);
  }
  why = "interpreter runs inline or interactive code";
  return SystemExe::No;
}

SystemExe judgeLink(ProcInfo& pi, std::string& why) {
  if (pi.linkTrust < 0) {
    pi.linkTrust = static_cast<int>(judgeLinkNow(pi, pi.linkWhy));
    if (pi.raced) pi.linkWhy += " (comm and exe did not settle)";
  }
  why = pi.linkWhy;
  return static_cast<SystemExe>(pi.linkTrust);
}

bool setuidRootProgram(const ProcInfo& pi) {
  return pi.exeStat && pi.exeSt.st_uid == 0 && (pi.exeSt.st_mode & S_ISUID);
}

}

void noteProcess(pid_t pid) {
  int cur = static_cast<int>(pid);
  for (int depth = 0; depth < 12 && cur > 1; ++depth) {
    ProcInfo pi;
    if (!readProc(cur, pi)) return;
    {
      std::lock_guard<std::mutex> lock(gSnapMu);
      auto it = gSnaps.find(cur);
      if (depth > 0 && it != gSnaps.end() && it->second.pi.start == pi.start) return;
    }
    std::string why;
    judgeLink(pi, why);
    storeSnap(pi);
    cur = pi.ppid;
  }
}

void forgetProcessesForTests() {
  std::lock_guard<std::mutex> lock(gSnapMu);
  gSnaps.clear();
}

std::string ActorVerdict::summary() const {
  std::string s = std::string(actorTrustName(trust)) + " pid=" + std::to_string(pid) +
                  " uid=" + std::to_string(uid) + " exe=" + exePath;
  if (!chrootRoot.empty()) s += " chroot=" + chrootRoot;
  for (const auto& r : reasons) s += "; " + r;
  return s;
}

const char* actorTrustName(ActorTrust t) {
  switch (t) {
  case ActorTrust::Trusted: return "trusted";
  case ActorTrust::Untrusted: return "untrusted";
  default: return "unattributed";
  }
}

ActorVerdict assessActor(pid_t pid) {
  ActorVerdict v;
  v.pid = static_cast<int>(pid);
  if (pid <= 0) { v.reasons.push_back("no process to attribute"); return v; }
  ProcInfo self;
  bool snap = false;
  if (!readActor(static_cast<int>(pid), self, snap)) {
    v.reasons.push_back("process already gone and not seen at exec");
    return v;
  }
  v.found = true;
  v.uid = self.euid;
  v.root = self.euid == 0;
  v.ppid = self.ppid;
  v.exePath = self.hostExe;
  v.shellLike = shellLikeName(baseName(self.exe));
  if (self.root != "/") v.chrootRoot = self.root;
  if (!self.exeDeleted && !self.exe.empty()) {
    if (self.root != "/") {
      v.exe = self.innerOk ? classifyInView(self.view, self.root, self.exe, nullptr) : SystemExe::No;
      if (snap && self.linkTrust >= 0 && !interpreter(baseName(self.exe)))
        v.exe = static_cast<SystemExe>(self.linkTrust);
    } else {
      v.exe = classifySystemExe(self.exe);
    }
    if (self.root != "/") v.exePath = self.root + self.exe;
  }
  if (snap) v.reasons.push_back("from exec snapshot");

  ProcInfo cur = self;
  ProcInfo child;
  bool haveChild = false;
  for (int depth = 0; depth < 32; ++depth) {
    const std::string tag = "pid " + std::to_string(cur.pid) + " ";
    if (cur.euid != 0) {
      if (haveChild && child.euid == 0 && setuidRootProgram(child)) {
        v.reasons.push_back(tag + "is the user who started an authorized elevation");
        v.trust = ActorTrust::Trusted;
        return v;
      }
      v.reasons.push_back(tag + (depth == 0 ? "is not root" : "non-root ancestor") + " uid=" +
                          std::to_string(cur.euid) + " " + cur.hostExe);
      v.trust = ActorTrust::Untrusted;
      return v;
    }
    if (cur.exe.empty() && cur.ppid == 0) {
      v.reasons.push_back(tag + "kernel thread");
      v.trust = ActorTrust::Trusted;
      return v;
    }
    std::string why;
    if (judgeLink(cur, why) == SystemExe::No) {
      v.reasons.push_back(tag + why);
      v.trust = ActorTrust::Untrusted;
      return v;
    }
    v.reasons.push_back(tag + why);
    if (cur.pid == 1) {
      v.reasons.push_back("service lineage from pid 1");
      v.trust = ActorTrust::Trusted;
      return v;
    }
    if (cur.ppid <= 0) {
      v.reasons.push_back(tag + "has no parent");
      v.trust = ActorTrust::Trusted;
      return v;
    }
    ProcInfo parent;
    bool ps = false;
    if (!readActor(cur.ppid, parent, ps)) {
      v.reasons.push_back("ancestor pid " + std::to_string(cur.ppid) + " is gone");
      v.trust = ActorTrust::Unattributed;
      return v;
    }
    child = cur;
    haveChild = true;
    cur = parent;
  }
  v.reasons.push_back("ancestry too deep");
  v.trust = ActorTrust::Untrusted;
  return v;
}

bool mayKill(const ActorVerdict& a) {
  if (a.trust == ActorTrust::Trusted) return false;
  if (a.root && a.exe == SystemExe::RpmVerified) return false;
  if (a.root && a.exe != SystemExe::No && !a.shellLike) return false;
  return true;
}

ProcessAction decideProcess(const ActorVerdict& a, bool exeBad, bool wantKill) {
  if (a.trust == ActorTrust::Trusted && !exeBad) return ProcessAction::Ignore;
  if (!wantKill || !mayKill(a)) return ProcessAction::AlertOnly;
  return ProcessAction::AlertAndKill;
}

}
}
