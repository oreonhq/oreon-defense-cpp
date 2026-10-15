#include "GuardMonitor.hpp"
#include "SystemTrust.hpp"
#include "ChangeAssess.hpp"
#include <thread>
#include <chrono>
#include <oreon/Paths.hpp>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <poll.h>
#include <unistd.h>
#include <pwd.h>
#include <cstring>
#include <algorithm>

namespace oreon {
namespace fs = std::filesystem;

static std::string readAll(const std::string& p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) return {};
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

std::vector<std::string> GuardMonitor::userHomes() const {
  std::vector<std::string> homes;
  if (isRoot()) {
    std::error_code ec;
    for (auto& e : fs::directory_iterator("/home", ec)) {
      if (e.is_directory()) homes.push_back(e.path().string());
    }
    if (fs::exists("/root")) homes.push_back("/root");
  } else {
    homes.push_back(homeDir());
  }
  return homes;
}

std::vector<std::string> GuardMonitor::placeCanaries() {
  std::vector<std::string> made;
  const char* subs[] = {"Documents", "Pictures", "Desktop", "Downloads"};
  for (const auto& home : userHomes()) {
    uid_t owner = 0;
    gid_t group = 0;
    struct stat hs{};
    if (stat(home.c_str(), &hs) == 0) { owner = hs.st_uid; group = hs.st_gid; }
    for (auto sub : subs) {
      std::string dir = home + "/" + sub;
      if (!fs::is_directory(dir)) continue;
      std::string c = dir + "/" + canaryName();
      if (!fs::exists(c)) {
        std::ofstream out(c);
        if (!out) continue;
        out << "Please keep this file. Oreon Defense uses it to detect\n"
               "programs that try to change your files without asking.\n";
        out.close();
        if (isRoot()) { if (chown(c.c_str(), owner, group) != 0) {} }
      }
      made.push_back(c);
    }
  }
  return made;
}

bool GuardMonitor::excluded(const std::string& path) const {
  for (const auto& e : exclusions_)
    if (!e.empty() && (path == e || path.rfind(e + "/", 0) == 0)) return true;
  return false;
}

void GuardMonitor::addWatch(const std::string& path, bool isCanary) {
  uint32_t mask = isCanary
    ? (IN_MODIFY | IN_ATTRIB | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE | IN_CREATE)
    : (IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_ATTRIB);
  int wd = inotify_add_watch(fd_, path.c_str(), mask);
  if (wd >= 0) {
    wd_[wd] = path;
    wdCanary_[wd] = isCanary;
  }
}

void GuardMonitor::seedPersistenceSnapshots() {
  persistPaths_.clear();
  std::vector<std::string> files;
  for (const auto& home : userHomes()) {
    for (const char* f : {"/.bashrc", "/.profile", "/.bash_profile",
                          "/.ssh/authorized_keys"})
      files.push_back(home + f);
  }
  for (const char* f : {"/etc/ld.so.preload", "/etc/passwd", "/etc/shadow", "/etc/group",
                        "/etc/gshadow", "/etc/sudoers"})
    files.push_back(f);
  for (const auto& f : files) {
    if (fs::exists(f)) snapshots_[f] = readAll(f);
    persistPaths_.push_back(f);
  }
}

bool GuardMonitor::start() {
  if (running_) return true;
  fd_ = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  if (fd_ < 0) return false;

  if (ransom_) {
    canaries_ = placeCanaries();
    std::vector<std::string> dirs;
    for (const auto& c : canaries_) dirs.push_back(fs::path(c).parent_path().string());
    std::sort(dirs.begin(), dirs.end());
    dirs.erase(std::unique(dirs.begin(), dirs.end()), dirs.end());
    for (const auto& d : dirs) addWatch(d, true);
  }

  if (persistence_ || privesc_) {
    seedPersistenceSnapshots();
    std::vector<std::string> watchDirs;
    for (const auto& home : userHomes()) {
      watchDirs.push_back(home);
      if (fs::is_directory(home + "/.ssh")) watchDirs.push_back(home + "/.ssh");
      if (fs::is_directory(home + "/.config/autostart")) watchDirs.push_back(home + "/.config/autostart");
      if (fs::is_directory(home + "/.config/systemd/user")) watchDirs.push_back(home + "/.config/systemd/user");
    }
    for (const char* d : {"/etc", "/etc/cron.d", "/etc/sudoers.d",
                          "/etc/systemd/system", "/var/spool/cron", "/etc/udev/rules.d"})
      if (fs::is_directory(d)) watchDirs.push_back(d);
    std::sort(watchDirs.begin(), watchDirs.end());
    watchDirs.erase(std::unique(watchDirs.begin(), watchDirs.end()), watchDirs.end());
    for (const auto& d : watchDirs) if (!excluded(d)) addWatch(d, false);
  }

  {
    std::vector<std::string> track;
    for (const auto& w : wd_) track.push_back(w.second);
    tracker_.start(track);
  }

  running_ = true;
  thr_ = std::thread([this] { loop(); });
  return true;
}

void GuardMonitor::stop() {
  if (!running_) return;
  running_ = false;
  if (thr_.joinable()) thr_.join();
  tracker_.stop();
  if (fd_ >= 0) { close(fd_); fd_ = -1; }
  wd_.clear();
  wdCanary_.clear();
}

void GuardMonitor::onCanaryEvent(const std::string& path, uint32_t) {
  if (!cb_) return;
  report(path, std::string("canary"), readAll(path));
}

void GuardMonitor::report(const std::string& path, const std::string& before, const std::string& after) {
  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  change::Event e;
  e.path = path;
  e.before = before;
  e.after = after;
  WriteTracker::Write w;
  if (tracker_.lookup(path, 5000, w)) {
    e.attributed = true;
    e.actor = w.actor;
  }
  if (!e.attributed && change::kindOf(path) != change::FileKind::Canary) e.packageCopy = change::matchesRpm(path);
  change::Verdict v = change::assess(e);
  std::string reasons;
  for (const auto& r : v.reasons) reasons += (reasons.empty() ? "" : "; ") + r;
  if (!v.alert) {
    if (info_) info_(path, reasons);
    return;
  }
  if (v.category == "privesc" && !privesc_) return;
  if (v.category == "persistence" && !persistence_) return;
  if (v.category == "ransomware" && !ransom_) return;
  Alert a;
  a.category = v.category;
  a.severity = v.severity;
  a.title = v.title;
  a.message = v.message;
  a.path = path;
  a.detail = v.detail;
  a.kill = v.killWriter;
  a.pid = e.attributed ? e.actor.pid : 0;
  a.reasons = reasons;
  cb_(a);
}

void GuardMonitor::onPersistenceEvent(const std::string& path) {
  if (!cb_) return;
  std::string before = snapshots_.count(path) ? snapshots_[path] : std::string();
  std::string after = readAll(path);
  if (after == before) return;
  snapshots_[path] = after;
  report(path, before, after);
}

void GuardMonitor::loop() {
  char buf[8192] __attribute__((aligned(__alignof__(struct inotify_event))));
  while (running_) {
    pollfd pfd{fd_, POLLIN, 0};
    if (poll(&pfd, 1, 500) <= 0) continue;
    ssize_t len = read(fd_, buf, sizeof(buf));
    if (len <= 0) continue;
    for (char* ptr = buf; ptr < buf + len; ) {
      auto* ev = reinterpret_cast<inotify_event*>(ptr);
      std::string dir;
      bool canary = false;
      {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = wd_.find(ev->wd);
        if (it != wd_.end()) { dir = it->second; canary = wdCanary_[ev->wd]; }
      }
      if (!dir.empty() && ev->len > 0) {
        std::string full = dir + "/" + ev->name;
        if (canary) {
          if (std::string(ev->name) == canaryName()) onCanaryEvent(full, ev->mask);
        } else {
          bool interesting;
          {
            std::lock_guard<std::mutex> lk(mu_);
            bool watched = snapshots_.count(full) ||
              std::find(persistPaths_.begin(), persistPaths_.end(), full) != persistPaths_.end();
            interesting = watched ||
              dir.find("/autostart") != std::string::npos ||
              dir.find("/cron") != std::string::npos ||
              dir.find("sudoers.d") != std::string::npos ||
              dir == "/etc/systemd/system" ||
              dir.find("/.ssh") != std::string::npos;
          }
          if (interesting) onPersistenceEvent(full);
        }
      }
      ptr += sizeof(inotify_event) + ev->len;
    }
  }
}

}
