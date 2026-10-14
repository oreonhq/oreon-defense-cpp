#include "ProcessMonitor.hpp"
#include "RuleEngine.hpp"
#include <filesystem>
#include <fstream>
#include <dirent.h>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <cstring>

namespace oreon {
namespace fs = std::filesystem;

bool ProcessMonitor::start() {
  if (running_) return true;
  running_ = true;
  thr_ = std::thread([this] { loop(); });
  return true;
}

void ProcessMonitor::stop() {
  if (!running_) return;
  running_ = false;
  if (thr_.joinable()) thr_.join();
}

void ProcessMonitor::loop() {
  // seed seen set first
  scanOnce();
  while (running_) {
    scanOnce();
    for (int i = 0; i < intervalMs_ / 100 && running_; ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

static std::string readFile(const std::string& path) {
  std::ifstream in(path);
  if (!in) return {};
  std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return s;
}

static std::string readCmdline(int pid) {
  std::ifstream in("/proc/" + std::to_string(pid) + "/cmdline");
  if (!in) return {};
  std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  for (char& c : s) if (c == '\0') c = ' ';
  while (!s.empty() && s.back() == ' ') s.pop_back();
  return s;
}

void ProcessMonitor::scanOnce() {
  DIR* d = opendir("/proc");
  if (!d) return;
  std::unordered_set<int> current;
  dirent* ent;
  while ((ent = readdir(d)) != nullptr) {
    if (ent->d_name[0] < '1' || ent->d_name[0] > '9') continue;
    int pid = atoi(ent->d_name);
    current.insert(pid);
    bool isNew = false;
    {
      std::lock_guard<std::mutex> lock(mu_);
      if (seen_.find(pid) == seen_.end()) {
        seen_.insert(pid);
        isNew = true;
      }
    }
    if (!isNew) continue;

    ProcessEvent pe;
    pe.pid = pid;
    pe.timestamp = nowEpoch();
    pe.cmdline = readCmdline(pid);
    pe.name = readFile("/proc/" + std::to_string(pid) + "/comm");
    while (!pe.name.empty() && (pe.name.back() == '\n' || pe.name.back() == '\r'))
      pe.name.pop_back();
    char link[512];
    ssize_t n = readlink(("/proc/" + std::to_string(pid) + "/exe").c_str(), link, sizeof(link) - 1);
    if (n > 0) {
      link[n] = 0;
      pe.exe = link;
    }
    std::string status = readFile("/proc/" + std::to_string(pid) + "/status");
    auto pos = status.find("PPid:");
    if (pos != std::string::npos) pe.ppid = atoi(status.c_str() + pos + 5);

    if (engine_) {
      auto m = engine_->matchProcess(pe.name, pe.cmdline, pe.exe);
      if (m.matched) {
        pe.suspicious = true;
        pe.reason = m.rule.name + " (" + m.detail + ")";
      }
    }

    // persistence locations in cmdline
    if (!pe.suspicious) {
      const char* hints[] = {
        "/.config/autostart", "/.bashrc", "/crontab", "systemctl enable",
        "/etc/cron", "chmod +x /tmp", "curl | sh", "wget | sh", "base64 -d"
      };
      for (auto h : hints) {
        if (pe.cmdline.find(h) != std::string::npos) {
          pe.suspicious = true;
          pe.reason = std::string("persistence or pipe-exec hint: ") + h;
          break;
        }
      }
    }

    if (cb_) cb_(pe);
  }
  closedir(d);

  std::lock_guard<std::mutex> lock(mu_);
  for (auto it = seen_.begin(); it != seen_.end(); ) {
    if (current.find(*it) == current.end()) it = seen_.erase(it);
    else ++it;
  }
}

} // namespace oreon
