#include "ProcessMonitor.hpp"
#include "SystemTrust.hpp"
#include "RuleEngine.hpp"
#include "CmdlineHeuristics.hpp"
#include <filesystem>
#include <fstream>
#include <dirent.h>
#include <unistd.h>
#include <poll.h>
#include <chrono>
#include <thread>
#include <cstring>
#include <cerrno>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <spawn.h>
#include <sys/wait.h>

namespace oreon {
namespace fs = std::filesystem;

std::string ProcessMonitor::mode() const {
  std::lock_guard<std::mutex> lock(mu_);
  return running_ ? mode_ : std::string("off");
}

std::string ProcessMonitor::lastError() const {
  std::lock_guard<std::mutex> lock(mu_);
  return lastError_;
}

bool ProcessMonitor::openNetlink(std::string* err) {
  int s = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_CONNECTOR);
  if (s < 0) {
    if (err) *err = std::string("netlink socket: ") + strerror(errno);
    return false;
  }
  int rcv = 4 * 1024 * 1024;
  setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &rcv, sizeof(rcv));
  sockaddr_nl addr{};
  addr.nl_family = AF_NETLINK;
  addr.nl_groups = CN_IDX_PROC;
  addr.nl_pid = 0;
  if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    if (err) *err = std::string("netlink bind: ") + strerror(errno);
    close(s);
    return false;
  }
  alignas(nlmsghdr) char req[NLMSG_SPACE(sizeof(cn_msg) + sizeof(proc_cn_mcast_op))] = {};
  auto* hdr = reinterpret_cast<nlmsghdr*>(req);
  hdr->nlmsg_len = NLMSG_LENGTH(sizeof(cn_msg) + sizeof(proc_cn_mcast_op));
  hdr->nlmsg_type = NLMSG_DONE;
  hdr->nlmsg_pid = static_cast<__u32>(getpid());
  auto* msg = static_cast<cn_msg*>(NLMSG_DATA(hdr));
  msg->id.idx = CN_IDX_PROC;
  msg->id.val = CN_VAL_PROC;
  msg->len = sizeof(proc_cn_mcast_op);
  proc_cn_mcast_op op = PROC_CN_MCAST_LISTEN;
  memcpy(msg->data, &op, sizeof(op));
  if (send(s, req, hdr->nlmsg_len, 0) < 0) {
    if (err) *err = std::string("netlink listen: ") + strerror(errno);
    close(s);
    return false;
  }
  nl_ = s;
  return true;
}

bool ProcessMonitor::start() {
  if (running_) return true;
  std::string err;
  bool nl = preferNetlink_ && openNetlink(&err);
  {
    std::lock_guard<std::mutex> lock(mu_);
    mode_ = nl ? "netlink" : "polling";
    lastError_ = err;
  }
  running_ = true;
  if (nl) {
    thr_ = std::thread([this] { netlinkLoop(); });
  } else {
    if (modeCb_) modeCb_("polling", err);
    thr_ = std::thread([this] { pollLoop(); });
  }
  return true;
}

void ProcessMonitor::stop() {
  if (!running_) return;
  running_ = false;
  if (thr_.joinable()) thr_.join();
  if (nl_ >= 0) {
    close(nl_);
    nl_ = -1;
  }
}

void ProcessMonitor::netlinkLoop() {
  alignas(nlmsghdr) char buf[8192];
  pid_t probe = -1;
  {
    const char* tru = access("/usr/bin/true", X_OK) == 0 ? "/usr/bin/true" : "/bin/true";
    char* const argv[] = {const_cast<char*>(tru), nullptr};
    char* const envp[] = {nullptr};
    if (posix_spawn(&probe, tru, nullptr, nullptr, argv, envp) != 0) probe = -1;
  }
  bool confirmed = probe <= 0;
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
  while (running_ && !confirmed && std::chrono::steady_clock::now() < deadline) {
    pollfd pfd{nl_, POLLIN, 0};
    if (poll(&pfd, 1, 200) <= 0) continue;
    ssize_t len = recv(nl_, buf, sizeof(buf), 0);
    if (len <= 0) continue;
    for (auto* h = reinterpret_cast<nlmsghdr*>(buf); NLMSG_OK(h, static_cast<unsigned>(len));
         h = NLMSG_NEXT(h, len)) {
      auto* cn = static_cast<cn_msg*>(NLMSG_DATA(h));
      if (cn->id.idx != CN_IDX_PROC || cn->id.val != CN_VAL_PROC) continue;
      auto* ev = reinterpret_cast<proc_event*>(cn->data);
      if (ev->what == PROC_EVENT_EXEC &&
          static_cast<pid_t>(ev->event_data.exec.process_tgid) == probe)
        confirmed = true;
    }
  }
  if (probe > 0) waitpid(probe, nullptr, 0);
  if (!confirmed) {
    {
      std::lock_guard<std::mutex> lock(mu_);
      mode_ = "polling";
      lastError_ = "proc connector sent no events (container or network namespace)";
    }
    close(nl_);
    nl_ = -1;
    if (modeCb_) modeCb_("polling", lastError_);
    pollLoop();
    return;
  }
  if (modeCb_) modeCb_("netlink", "");
  while (running_) {
    pollfd pfd{nl_, POLLIN, 0};
    int pr = poll(&pfd, 1, 500);
    if (pr <= 0) continue;
    ssize_t len = recv(nl_, buf, sizeof(buf), 0);
    if (len < 0) {
      if (errno == ENOBUFS) {
        scanOnce();
      }
      continue;
    }
    for (auto* h = reinterpret_cast<nlmsghdr*>(buf); NLMSG_OK(h, static_cast<unsigned>(len));
         h = NLMSG_NEXT(h, len)) {
      if (h->nlmsg_type == NLMSG_ERROR || h->nlmsg_type == NLMSG_NOOP) continue;
      auto* cn = static_cast<cn_msg*>(NLMSG_DATA(h));
      if (cn->id.idx != CN_IDX_PROC || cn->id.val != CN_VAL_PROC) continue;
      auto* ev = reinterpret_cast<proc_event*>(cn->data);
      if (ev->what == PROC_EVENT_EXEC) {
        handlePid(static_cast<int>(ev->event_data.exec.process_tgid));
      }
    }
  }
}

void ProcessMonitor::pollLoop() {
  scanOnce();
  while (running_) {
    scanOnce();
    for (int i = 0; i < intervalMs_ / 100 && running_; ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

static std::string readSmall(const std::string& path) {
  std::ifstream in(path);
  if (!in) return {};
  std::string s;
  s.resize(65536);
  in.read(s.data(), static_cast<std::streamsize>(s.size()));
  s.resize(static_cast<size_t>(in.gcount()));
  return s;
}

namespace {
std::string baseOf(const std::string& p) {
  auto s = p.find_last_of('/');
  return s == std::string::npos ? p : p.substr(s + 1);
}
}

bool ProcessMonitor::consistent(const ProcessEvent& pe) {
  if (pe.exe.empty() || pe.name.empty()) return true;
  std::string eb = baseOf(pe.exe);
  const std::string del = " (deleted)";
  if (eb.size() > del.size() && eb.compare(eb.size() - del.size(), del.size(), del) == 0)
    eb.resize(eb.size() - del.size());
  if (eb.compare(0, 15, pe.name, 0, 15) == 0) return true;
  for (size_t i = 0; i < pe.argv.size() && i < 4; ++i)
    if (baseOf(pe.argv[i]).compare(0, 15, pe.name, 0, 15) == 0 && i > 0) return true;
  return false;
}

bool ProcessMonitor::readProcess(int pid, ProcessEvent& pe) {
  const std::string base = "/proc/" + std::to_string(pid);
  for (int attempt = 0; attempt < 6; ++attempt) {
    if (attempt) std::this_thread::sleep_for(std::chrono::milliseconds(2));
    pe = ProcessEvent{};
    pe.pid = pid;
    pe.timestamp = nowEpoch();
    const std::string raw = readSmall(base + "/cmdline");
    size_t start = 0;
    for (size_t i = 0; i <= raw.size(); ++i) {
      if (i == raw.size() || raw[i] == '\0') {
        if (i > start) pe.argv.push_back(raw.substr(start, i - start));
        start = i + 1;
      }
    }
    pe.cmdline = raw;
    for (char& c : pe.cmdline) if (c == '\0') c = ' ';
    while (!pe.cmdline.empty() && pe.cmdline.back() == ' ') pe.cmdline.pop_back();
    pe.name = readSmall(base + "/comm");
    while (!pe.name.empty() && (pe.name.back() == '\n' || pe.name.back() == '\r'))
      pe.name.pop_back();
    char link[4096];
    ssize_t n = readlink((base + "/exe").c_str(), link, sizeof(link) - 1);
    if (n > 0) {
      link[n] = 0;
      pe.exe = link;
    }
    std::string status = readSmall(base + "/status");
    auto pos = status.find("PPid:");
    if (pos != std::string::npos) pe.ppid = atoi(status.c_str() + pos + 5);
    if (consistent(pe)) break;
  }
  return !pe.name.empty() || !pe.cmdline.empty();
}

void ProcessMonitor::handlePid(int pid) {
  static const int self = getpid();
  if (pid <= 1 || pid == self) return;
  ProcessEvent pe;
  if (!readProcess(pid, pe)) return;
  if (pe.ppid == self) return;
  if (pe.exe.empty() && pe.cmdline.empty()) return;
  trust::noteProcess(pid);

  if (engine_) {
    auto m = engine_->matchProcess(pe.name, pe.cmdline, pe.exe);
    if (m.matched) {
      pe.suspicious = true;
      pe.reason = m.rule.name + " (" + m.detail + ")";
      pe.ruleId = m.rule.id;
      pe.kill = m.rule.kill && (m.detail != "cmdline pattern" || m.rule.killCmdline);
      pe.severity = m.rule.severity;
    }
  }

  if (!pe.suspicious) {
    const auto hit = heuristics::strongProcessPattern(pe.argv, pe.exe);
    if (hit.matched) {
      pe.suspicious = true;
      pe.reason = "reverse shell or remote-control pattern: " + hit.pattern;
      pe.ruleId = "reverse-shell";
      pe.kill = true;
      pe.severity = Severity::High;
    }
    if (!pe.suspicious) {
      const char* hints[] = {
        "/crontab", "/etc/cron", "chmod +x /tmp",
        "curl | sh", "wget | sh", "curl | bash", "wget | bash", "base64 -d"
      };
      for (auto h : hints) {
        if (pe.cmdline.find(h) != std::string::npos) {
          pe.suspicious = true;
          pe.reason = std::string("persistence or pipe-exec hint: ") + h;
          pe.ruleId = "process-heuristic";
          pe.kill = false;
          pe.severity = Severity::Medium;
          break;
        }
      }
    }
  }

  if (cb_) cb_(pe);
}

void ProcessMonitor::scanOnce() {
  DIR* d = opendir("/proc");
  if (!d) return;
  std::unordered_set<int> current;
  std::vector<int> fresh;
  bool seeding;
  {
    std::lock_guard<std::mutex> lock(mu_);
    seeding = seen_.empty();
  }
  dirent* ent;
  while ((ent = readdir(d)) != nullptr) {
    if (ent->d_name[0] < '1' || ent->d_name[0] > '9') continue;
    int pid = atoi(ent->d_name);
    current.insert(pid);
    std::lock_guard<std::mutex> lock(mu_);
    if (seen_.insert(pid).second && !seeding) fresh.push_back(pid);
  }
  closedir(d);
  {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto it = seen_.begin(); it != seen_.end(); ) {
      if (current.find(*it) == current.end()) it = seen_.erase(it);
      else ++it;
    }
  }
  for (int pid : fresh) handlePid(pid);
}

} // namespace oreon
