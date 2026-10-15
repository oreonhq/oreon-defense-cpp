#include "OnAccessMonitor.hpp"
#include <sys/fanotify.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <set>
#include <algorithm>

#ifndef FAN_OPEN_EXEC_PERM
#define FAN_OPEN_EXEC_PERM 0x00040000
#endif
#ifndef FAN_MARK_FILESYSTEM
#define FAN_MARK_FILESYSTEM 0x00000100
#endif

namespace oreon {

static int64_t monoMs() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

static constexpr size_t kMaxQueue = 2048;
static constexpr size_t kMaxCache = 65536;
static constexpr uint64_t kMaxIgnoreMarks = 32768;

OnAccessMonitor::OnAccessMonitor() = default;
OnAccessMonitor::~OnAccessMonitor() { stop(); }

void OnAccessMonitor::setPaths(const std::vector<std::string>& p) { paths_ = p; }
void OnAccessMonitor::setExclusions(const std::vector<std::string>& e) { exclusions_ = e; }

static bool under(const std::string& path, const std::string& dir) {
  if (dir.empty()) return false;
  if (dir == "/") return true;
  return path == dir || (path.size() > dir.size() && path.compare(0, dir.size(), dir) == 0 &&
                         path[dir.size()] == '/');
}

bool OnAccessMonitor::inScope(const std::string& path) const {
  bool in = false;
  for (const auto& p : paths_)
    if (under(path, p)) { in = true; break; }
  if (!in) return false;
  for (const auto& e : exclusions_)
    if (under(path, e)) return false;
  if (path.find("/oreon-defense/") != std::string::npos) return false;
  return true;
}

bool OnAccessMonitor::start(std::string* err) {
  if (running_) return true;
  self_ = getpid();
  unsigned initFlags = FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK |
                       FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS;
  fan_ = fanotify_init(initFlags, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
  if (fan_ < 0) {
    if (err) *err = std::string("fanotify_init: ") + strerror(errno);
    return false;
  }

  uint64_t mask = FAN_OPEN_EXEC_PERM | (scanOpen_ ? FAN_OPEN_PERM : 0);
  bool execPerm = true;
  std::string mode;
  std::set<dev_t> seen;
  std::vector<std::string> marked;
  std::string lastErr;
  for (const auto& p : paths_) {
    struct stat st{};
    if (stat(p.c_str(), &st) != 0) continue;
    if (!seen.insert(st.st_dev).second) continue;
    auto tryMark = [&](unsigned how) {
      int rc = fanotify_mark(fan_, FAN_MARK_ADD | how, mask, AT_FDCWD, p.c_str());
      if (rc != 0 && errno == EINVAL && (mask & FAN_OPEN_EXEC_PERM)) {
        execPerm = false;
        mask = FAN_OPEN_PERM;
        rc = fanotify_mark(fan_, FAN_MARK_ADD | how, mask, AT_FDCWD, p.c_str());
      }
      return rc == 0;
    };
    if (tryMark(FAN_MARK_FILESYSTEM)) {
      mode = "filesystem";
      marked.push_back(p);
    } else if (tryMark(FAN_MARK_MOUNT)) {
      if (mode.empty()) mode = "mount";
      marked.push_back(p);
    } else {
      lastErr = p + ": " + strerror(errno);
    }
  }
  if (marked.empty()) {
    close(fan_);
    fan_ = -1;
    if (err) *err = lastErr.empty() ? "no on-access paths exist" : "fanotify_mark " + lastErr;
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(smu_);
    stats_ = Stats{};
    stats_.markMode = mode;
    stats_.execPerm = execPerm;
    stats_.marked = marked;
  }
  wakeFd_ = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  running_ = true;
  unsigned n = std::max(2u, std::min(4u, std::thread::hardware_concurrency()));
  for (unsigned i = 0; i < n; ++i) workers_.emplace_back([this] { workerLoop(); });
  watchdog_ = std::thread([this] { watchdogLoop(); });
  reader_ = std::thread([this] { readerLoop(); });
  return true;
}

void OnAccessMonitor::stop() {
  if (!running_) return;
  running_ = false;
  if (wakeFd_ >= 0) {
    uint64_t one = 1;
    (void)!write(wakeFd_, &one, sizeof(one));
  }
  qcv_.notify_all();
  if (reader_.joinable()) reader_.join();
  for (auto& w : workers_)
    if (w.joinable()) w.join();
  workers_.clear();
  if (watchdog_.joinable()) watchdog_.join();
  {
    std::lock_guard<std::mutex> lock(qmu_);
    for (auto& j : queue_) {
      answer(j, true);
      close(j->fd);
    }
    queue_.clear();
  }
  {
    std::lock_guard<std::mutex> lock(pmu_);
    pending_.clear();
  }
  if (fan_ >= 0) close(fan_);
  fan_ = -1;
  if (wakeFd_ >= 0) close(wakeFd_);
  wakeFd_ = -1;
  std::lock_guard<std::mutex> lock(cmu_);
  cache_.clear();
  ignoreMarks_ = 0;
}

void OnAccessMonitor::respond(int fd, bool allow) {
  fanotify_response r{};
  r.fd = fd;
  r.response = allow ? FAN_ALLOW : FAN_DENY;
  std::lock_guard<std::mutex> lock(wmu_);
  if (fan_ >= 0) (void)!write(fan_, &r, sizeof(r));
}

void OnAccessMonitor::answer(const std::shared_ptr<Job>& j, bool allow) {
  bool expected = false;
  if (j->answered.compare_exchange_strong(expected, true)) respond(j->fd, allow);
}

void OnAccessMonitor::addIgnoreMark(int fd) {
  if (ignoreMarks_ >= kMaxIgnoreMarks) {
    fanotify_mark(fan_, FAN_MARK_FLUSH, 0, AT_FDCWD, nullptr);
    ignoreMarks_ = 0;
  }
  if (fanotify_mark(fan_, FAN_MARK_ADD | FAN_MARK_IGNORED_MASK,
                    FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM, fd, nullptr) == 0)
    ++ignoreMarks_;
}

void OnAccessMonitor::clearCache() {
  {
    std::lock_guard<std::mutex> lock(cmu_);
    cache_.clear();
  }
  if (fan_ >= 0) {
    fanotify_mark(fan_, FAN_MARK_FLUSH, 0, AT_FDCWD, nullptr);
    ignoreMarks_ = 0;
  }
}

bool OnAccessMonitor::cacheHit(const std::string& key) {
  std::lock_guard<std::mutex> lock(cmu_);
  return cache_.count(key) > 0;
}

void OnAccessMonitor::cachePut(const std::string& key) {
  std::lock_guard<std::mutex> lock(cmu_);
  if (cache_.size() >= kMaxCache) cache_.clear();
  cache_[key] = monoMs();
}

OnAccessMonitor::Stats OnAccessMonitor::stats() const {
  std::lock_guard<std::mutex> lock(smu_);
  return stats_;
}

void OnAccessMonitor::readerLoop() {
  alignas(fanotify_event_metadata) char buf[16384];
  while (running_) {
    pollfd pfd[2] = {{fan_, POLLIN, 0}, {wakeFd_, POLLIN, 0}};
    int pr = poll(pfd, 2, 500);
    if (pr <= 0) continue;
    if (pfd[1].revents & POLLIN) break;
    ssize_t len = read(fan_, buf, sizeof(buf));
    if (len <= 0) continue;
    auto* md = reinterpret_cast<fanotify_event_metadata*>(buf);
    for (; FAN_EVENT_OK(md, len); md = FAN_EVENT_NEXT(md, len)) {
      if (md->vers != FANOTIFY_METADATA_VERSION) continue;
      if (md->fd < 0) continue;
      const bool perm = md->mask & (FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM);
      const bool exec = md->mask & FAN_OPEN_EXEC_PERM;
      {
        std::lock_guard<std::mutex> lock(smu_);
        ++stats_.events;
      }
      if (!perm) {
        close(md->fd);
        continue;
      }
      if (md->pid == self_) {
        respond(md->fd, true);
        close(md->fd);
        continue;
      }
      struct stat st{};
      if (fstat(md->fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        respond(md->fd, true);
        close(md->fd);
        continue;
      }
      char link[64];
      snprintf(link, sizeof(link), "/proc/self/fd/%d", md->fd);
      char pathBuf[4096];
      ssize_t n = readlink(link, pathBuf, sizeof(pathBuf) - 1);
      std::string path = n > 0 ? std::string(pathBuf, static_cast<size_t>(n)) : std::string();
      if (path.empty() || !inScope(path)) {
        respond(md->fd, true);
        addIgnoreMark(md->fd);
        close(md->fd);
        continue;
      }
      if (static_cast<uint64_t>(st.st_size) > maxBytes_ || st.st_size == 0) {
        respond(md->fd, true);
        close(md->fd);
        continue;
      }
      std::string key = std::to_string(st.st_dev) + ":" + std::to_string(st.st_ino) + ":" +
                        std::to_string(st.st_mtim.tv_sec) + "." + std::to_string(st.st_mtim.tv_nsec) +
                        ":" + std::to_string(st.st_size);
      if (cacheHit(key)) {
        {
          std::lock_guard<std::mutex> lock(smu_);
          ++stats_.cacheHits;
        }
        respond(md->fd, true);
        close(md->fd);
        continue;
      }
      auto job = std::make_shared<Job>();
      job->fd = md->fd;
      job->pid = md->pid;
      job->exec = exec;
      job->path = path;
      job->key = key;
      job->size = static_cast<uint64_t>(st.st_size);
      job->deadlineMs = monoMs() + timeoutMs_;
      bool queued = false;
      {
        std::lock_guard<std::mutex> lock(qmu_);
        if (queue_.size() < kMaxQueue) {
          queue_.push_back(job);
          queued = true;
        }
      }
      if (!queued) {
        respond(md->fd, true);
        close(md->fd);
        continue;
      }
      {
        std::lock_guard<std::mutex> lock(pmu_);
        pending_.push_back(job);
      }
      qcv_.notify_one();
    }
  }
}

void OnAccessMonitor::workerLoop() {
  while (running_) {
    std::shared_ptr<Job> job;
    {
      std::unique_lock<std::mutex> lock(qmu_);
      qcv_.wait_for(lock, std::chrono::milliseconds(500),
                    [this] { return !queue_.empty() || !running_; });
      if (!running_) return;
      if (queue_.empty()) continue;
      job = queue_.front();
      queue_.pop_front();
    }
    Detection d;
    if (scan_) d = scan_(job->fd, job->path, job->pid, job->exec);
    {
      std::lock_guard<std::mutex> lock(smu_);
      ++stats_.scanned;
    }
    bool timedOut = job->answered.load();
    if (d.matched) {
      answer(job, false);
      std::lock_guard<std::mutex> lock(smu_);
      ++stats_.denied;
    } else {
      answer(job, true);
      if (d.cacheable) {
        cachePut(job->key);
        addIgnoreMark(job->fd);
      }
    }
    close(job->fd);
    {
      std::lock_guard<std::mutex> lock(pmu_);
      pending_.remove(job);
    }
    if (d.matched && deny_) deny_(job->path, job->pid, job->exec, d, timedOut);
  }
}

void OnAccessMonitor::watchdogLoop() {
  while (running_) {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    int64_t now = monoMs();
    std::vector<std::shared_ptr<Job>> late;
    {
      std::lock_guard<std::mutex> lock(pmu_);
      for (auto& j : pending_)
        if (!j->answered && now >= j->deadlineMs) late.push_back(j);
    }
    for (auto& j : late) {
      bool expected = false;
      if (j->answered.compare_exchange_strong(expected, true)) {
        respond(j->fd, true);
        std::lock_guard<std::mutex> lock(smu_);
        ++stats_.timeouts;
      }
    }
  }
}

}
