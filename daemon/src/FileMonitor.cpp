#include "FileMonitor.hpp"
#include <oreon/Paths.hpp>
#include <filesystem>
#include <unistd.h>
#include <poll.h>
#include <cstring>
#include <iostream>

namespace oreon {
namespace fs = std::filesystem;

FileMonitor::FileMonitor() = default;

FileMonitor::~FileMonitor() { stop(); }

void FileMonitor::setPaths(const std::vector<std::string>& paths) {
  std::lock_guard<std::mutex> lock(mu_);
  paths_ = paths;
}

void FileMonitor::setExclusions(const std::vector<std::string>& excl) {
  std::lock_guard<std::mutex> lock(mu_);
  exclusions_ = excl;
}

void FileMonitor::setCallback(Callback cb) { cb_ = std::move(cb); }

bool FileMonitor::isExcluded(const std::string& path) const {
  for (const auto& e : exclusions_) {
    if (e.empty()) continue;
    if (path == e || path.find(e + "/") == 0) return true;
  }
  // Always ignore our own package/state paths to avoid feedback loops.
  if (path.find("/oreon-defense/") != std::string::npos) return true;
  return false;
}

void FileMonitor::addWatchRecursive(const std::string& path, int depth) {
  if (depth > 6) return;
  if (!fs::exists(path) || !fs::is_directory(path)) return;
  if (isExcluded(path)) return;

  uint32_t mask = IN_CREATE | IN_MODIFY | IN_MOVED_TO | IN_CLOSE_WRITE | IN_DELETE;
  int wd = inotify_add_watch(fd_, path.c_str(), mask);
  if (wd >= 0) wdToPath_[wd] = path;

  std::error_code ec;
  for (auto& e : fs::directory_iterator(path, ec)) {
    if (ec) break;
    if (e.is_directory()) addWatchRecursive(e.path().string(), depth + 1);
  }
}

bool FileMonitor::start() {
  if (running_) return true;
  fd_ = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  if (fd_ < 0) {
    std::cerr << "inotify_init failed\n";
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(mu_);
    wdToPath_.clear();
    for (const auto& p : paths_) addWatchRecursive(p);
  }
  running_ = true;
  thr_ = std::thread([this] { loop(); });
  return true;
}

void FileMonitor::stop() {
  if (!running_) return;
  running_ = false;
  if (thr_.joinable()) thr_.join();
  if (fd_ >= 0) {
    close(fd_);
    fd_ = -1;
  }
  wdToPath_.clear();
}

void FileMonitor::loop() {
  char buf[4096]
    __attribute__((aligned(__alignof__(struct inotify_event))));
  while (running_) {
    pollfd pfd{fd_, POLLIN, 0};
    int pr = poll(&pfd, 1, 500);
    if (pr <= 0) continue;
    ssize_t len = read(fd_, buf, sizeof(buf));
    if (len <= 0) continue;
    for (char* ptr = buf; ptr < buf + len; ) {
      auto* ev = reinterpret_cast<inotify_event*>(ptr);
      std::string dir;
      {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = wdToPath_.find(ev->wd);
        if (it != wdToPath_.end()) dir = it->second;
      }
      if (!dir.empty() && ev->len > 0) {
        std::string full = dir + "/" + ev->name;
        if (!isExcluded(full)) {
          FileEvent fe;
          fe.path = full;
          fe.timestamp = nowEpoch();
          if (ev->mask & (IN_CREATE | IN_MOVED_TO)) fe.op = "create";
          else if (ev->mask & IN_MODIFY || ev->mask & IN_CLOSE_WRITE) fe.op = "modify";
          else if (ev->mask & IN_DELETE) fe.op = "delete";
          else fe.op = "other";

          if ((ev->mask & IN_ISDIR) && (ev->mask & (IN_CREATE | IN_MOVED_TO))) {
            std::lock_guard<std::mutex> lock(mu_);
            addWatchRecursive(full);
          }
          if (cb_ && fe.op != "other" && fe.op != "delete") cb_(fe);
        }
      }
      ptr += sizeof(inotify_event) + ev->len;
    }
  }
}

} // namespace oreon
