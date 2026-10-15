#include "WriteTracker.hpp"
#include <chrono>
#include <climits>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/fanotify.h>
#include <unistd.h>

#ifndef FAN_REPORT_PIDFD
#define FAN_REPORT_PIDFD 0x00000080
#endif
#ifndef FAN_REPORT_DIR_FID
#define FAN_REPORT_DIR_FID 0x00000400
#endif
#ifndef FAN_REPORT_NAME
#define FAN_REPORT_NAME 0x00000800
#endif
#ifndef FAN_REPORT_DFID_NAME
#define FAN_REPORT_DFID_NAME (FAN_REPORT_DIR_FID | FAN_REPORT_NAME)
#endif
#ifndef FAN_EVENT_INFO_TYPE_DFID_NAME
#define FAN_EVENT_INFO_TYPE_DFID_NAME 2
#endif
#ifndef FAN_EVENT_INFO_TYPE_PIDFD
#define FAN_EVENT_INFO_TYPE_PIDFD 4
#endif
#ifndef FAN_MOVED_TO
#define FAN_MOVED_TO 0x00000080
#endif
#ifndef FAN_CREATE
#define FAN_CREATE 0x00000100
#endif

namespace oreon {

static int64_t nowMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::steady_clock::now().time_since_epoch()).count();
}

static std::string handleKey(const struct file_handle* fh) {
  std::string k(reinterpret_cast<const char*>(&fh->handle_type), sizeof(fh->handle_type));
  k.append(reinterpret_cast<const char*>(fh->f_handle), fh->handle_bytes);
  return k;
}

static std::string dirOf(const std::string& p) {
  auto s = p.rfind('/');
  return s == std::string::npos || s == 0 ? std::string("/") : p.substr(0, s);
}

bool WriteTracker::start(const std::vector<std::string>& dirs) {
  if (running_) return true;
  const unsigned int base = FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK;
  const unsigned int tries[] = {base | FAN_REPORT_DFID_NAME | FAN_REPORT_PIDFD,
                                base | FAN_REPORT_DFID_NAME, base | FAN_REPORT_PIDFD, base};
  for (unsigned int flags : tries) {
    fd_ = fanotify_init(flags, O_RDONLY | O_CLOEXEC | O_LARGEFILE);
    if (fd_ >= 0) {
      fidMode_ = (flags & FAN_REPORT_DFID_NAME) != 0;
      mode_ = std::string(fidMode_ ? "fanotify name" : "fanotify fd") +
              ((flags & FAN_REPORT_PIDFD) ? " + pidfd" : "");
      break;
    }
  }
  if (fd_ < 0) { mode_ = std::string("unavailable: ") + strerror(errno); return false; }
  uint64_t mask = FAN_MODIFY | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD;
  if (fidMode_) mask |= FAN_MOVED_TO | FAN_CREATE;
  int marked = 0;
  for (const auto& d : dirs) {
    if (fanotify_mark(fd_, FAN_MARK_ADD, mask, AT_FDCWD, d.c_str()) != 0) continue;
    ++marked;
    if (fidMode_) {
      char buf[sizeof(struct file_handle) + MAX_HANDLE_SZ];
      auto* fh = reinterpret_cast<struct file_handle*>(buf);
      fh->handle_bytes = MAX_HANDLE_SZ;
      int mnt = 0;
      if (name_to_handle_at(AT_FDCWD, d.c_str(), fh, &mnt, 0) == 0) handles_[handleKey(fh)] = d;
    }
  }
  if (marked == 0) { close(fd_); fd_ = -1; mode_ = "unavailable: no folder could be marked"; return false; }
  running_ = true;
  thr_ = std::thread([this] { loop(); });
  return true;
}

void WriteTracker::stop() {
  if (!running_) return;
  running_ = false;
  if (thr_.joinable()) thr_.join();
  if (fd_ >= 0) { close(fd_); fd_ = -1; }
}

void WriteTracker::recordVerdict(const std::string& path, const trust::ActorVerdict& v) {
  Write w;
  w.path = path;
  w.dir = dirOf(path);
  w.atMs = nowMs();
  w.actor = v;
  std::lock_guard<std::mutex> lock(mu_);
  recent_.push_back(std::move(w));
  while (recent_.size() > 512) recent_.pop_front();
}

void WriteTracker::record(const std::string& path, pid_t pid) {
  recordVerdict(path, trust::assessActor(pid));
}

bool WriteTracker::lookup(const std::string& path, int64_t windowMs, Write& out) const {
  const int64_t now = nowMs();
  const std::string dir = dirOf(path);
  std::lock_guard<std::mutex> lock(mu_);
  const Write* sameDir = nullptr;
  for (auto it = recent_.rbegin(); it != recent_.rend(); ++it) {
    if (now - it->atMs > windowMs) break;
    if (it->path == path) { out = *it; return true; }
    if (!sameDir && (it->dir == dir || it->path == dir)) sameDir = &*it;
  }
  if (sameDir) { out = *sameDir; return true; }
  return false;
}

void WriteTracker::handleBuffer(const char* buf, ssize_t len) {
  auto* md = reinterpret_cast<const struct fanotify_event_metadata*>(buf);
  while (FAN_EVENT_OK(md, len)) {
    if (md->vers != FANOTIFY_METADATA_VERSION) return;
    std::string path;
    int pidfd = -1;
    if (md->fd >= 0) {
      char link[64], target[PATH_MAX];
      snprintf(link, sizeof(link), "/proc/self/fd/%d", md->fd);
      ssize_t n = readlink(link, target, sizeof(target) - 1);
      if (n > 0) path.assign(target, static_cast<size_t>(n));
      close(md->fd);
    }
    const char* p = reinterpret_cast<const char*>(md) + md->metadata_len;
    const char* end = reinterpret_cast<const char*>(md) + md->event_len;
    while (p + sizeof(struct fanotify_event_info_header) <= end) {
      auto* hdr = reinterpret_cast<const struct fanotify_event_info_header*>(p);
      if (hdr->len == 0 || p + hdr->len > end) break;
      if (hdr->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {
        auto* fid = reinterpret_cast<const struct fanotify_event_info_fid*>(p);
        auto* fh = reinterpret_cast<const struct file_handle*>(fid->handle);
        const char* name = reinterpret_cast<const char*>(fh->f_handle) + fh->handle_bytes;
        auto it = handles_.find(handleKey(fh));
        if (it != handles_.end()) {
          path = it->second;
          if (name < end && *name && strcmp(name, ".") != 0) path += "/" + std::string(name);
        }
      } else if (hdr->info_type == FAN_EVENT_INFO_TYPE_PIDFD) {
        pidfd = reinterpret_cast<const struct fanotify_event_info_pidfd*>(p)->pidfd;
      }
      p += hdr->len;
    }
    if (!path.empty() && md->pid > 0 && md->pid != getpid()) {
      record(path, md->pid);
    }
    if (pidfd >= 0) close(pidfd);
    md = FAN_EVENT_NEXT(md, len);
  }
}

void WriteTracker::loop() {
  alignas(struct fanotify_event_metadata) char buf[16384];
  while (running_) {
    pollfd pfd{fd_, POLLIN, 0};
    if (poll(&pfd, 1, 500) <= 0) continue;
    ssize_t len = read(fd_, buf, sizeof(buf));
    if (len <= 0) continue;
    handleBuffer(buf, len);
  }
}

}
