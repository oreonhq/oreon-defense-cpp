#include "Quarantine.hpp"
#include <oreon/JsonUtil.hpp>
#include <oreon/Hash.hpp>
#include <oreon/Paths.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <random>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

namespace oreon {
namespace fs = std::filesystem;

static std::string makeId() {
  static std::mt19937_64 rng{std::random_device{}()};
  return "q-" + std::to_string(nowEpoch()) + "-" + std::to_string(rng() & 0xffffff);
}

void Quarantine::setDir(const std::string& dir) {
  std::lock_guard<std::mutex> lock(mu_);
  dir_ = dir;
  ensureDir(dir_);
  ensureDir(dir_ + "/data");
  ensureDir(dir_ + "/meta");
}

bool Quarantine::saveMeta(const QuarantineItem& item) const {
  std::ofstream out(item.metaPath);
  if (!out) return false;
  out << quarantineToJson(item).dump(2) << "\n";
  out.flush();
  return static_cast<bool>(out);
}

static void setErr(std::string* err, const std::string& what, int e) {
  if (err) *err = what + ": " + std::strerror(e);
}

bool Quarantine::moveFile(const std::string& from, const std::string& to, int mode, std::string* err) {
  if (::rename(from.c_str(), to.c_str()) == 0) {
    ::chmod(to.c_str(), static_cast<mode_t>(mode));
    return true;
  }
  if (errno != EXDEV) {
    setErr(err, "cannot move " + from, errno);
    return false;
  }
  int in = ::open(from.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (in < 0) { setErr(err, "cannot open " + from, errno); return false; }
  int out = ::open(to.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, static_cast<mode_t>(mode));
  if (out < 0) { int e = errno; ::close(in); setErr(err, "cannot create " + to, e); return false; }
  char buf[65536];
  bool ok = true;
  int e = 0;
  for (;;) {
    ssize_t n = ::read(in, buf, sizeof(buf));
    if (n == 0) break;
    if (n < 0) { if (errno == EINTR) continue; ok = false; e = errno; break; }
    ssize_t off = 0;
    while (off < n) {
      ssize_t w = ::write(out, buf + off, static_cast<size_t>(n - off));
      if (w < 0) { if (errno == EINTR) continue; ok = false; e = errno; break; }
      off += w;
    }
    if (!ok) break;
  }
  if (ok && ::fsync(out) != 0) { ok = false; e = errno; }
  if (::close(out) != 0 && ok) { ok = false; e = errno; }
  ::close(in);
  if (!ok) { ::unlink(to.c_str()); setErr(err, "cannot copy " + from, e); return false; }
  ::fchmodat(AT_FDCWD, to.c_str(), static_cast<mode_t>(mode), 0);
  if (::unlink(from.c_str()) != 0) {
    e = errno;
    ::unlink(to.c_str());
    setErr(err, "cannot remove " + from, e);
    return false;
  }
  return true;
}

void Quarantine::reload() {
  std::lock_guard<std::mutex> lock(mu_);
  items_.clear();
  std::error_code ec;
  for (auto& e : fs::directory_iterator(dir_ + "/meta", ec)) {
    if (!e.is_regular_file()) continue;
    std::ifstream in(e.path());
    if (!in) continue;
    try {
      json j;
      in >> j;
      QuarantineItem item;
      item.id = j.value("id", "");
      item.originalPath = j.value("originalPath", "");
      item.threatName = j.value("threatName", "");
      item.sha256 = j.value("sha256", "");
      item.severity = severityFromString(j.value("severity", "medium"));
      item.quarantinedAt = j.value("quarantinedAt", int64_t{0});
      item.metaPath = e.path().string();
      item.dataPath = j.value("dataPath", dir_ + "/data/" + item.id + ".bin");
      item.ownerUid = j.value("ownerUid", -1);
      item.originUrl = j.value("originUrl", "");
      item.originalMode = j.value("originalMode", 0600);
      if (!item.id.empty()) items_.push_back(item);
    } catch (...) {}
  }
}

std::optional<QuarantineItem> Quarantine::quarantineFile(const std::string& path, const Threat& threat,
                                                         std::string* err) {
  std::lock_guard<std::mutex> lock(mu_);
  struct stat lst{};
  if (::lstat(path.c_str(), &lst) != 0) { setErr(err, "cannot find " + path, errno); return std::nullopt; }
  if (!S_ISREG(lst.st_mode)) { if (err) *err = "not a regular file"; return std::nullopt; }
  if (dir_.empty() || path == dir_ || path.find(dir_ + "/") == 0) {
    if (err) *err = "already in quarantine";
    return std::nullopt;
  }

  QuarantineItem item;
  item.id = makeId();
  item.originalPath = path;
  item.threatName = threat.name.empty() ? "Unknown threat" : threat.name;
  item.sha256 = threat.sha256.empty() ? sha256File(path) : threat.sha256;
  item.severity = threat.severity;
  item.quarantinedAt = nowEpoch();
  struct stat ost{};
  if (::stat(path.c_str(), &ost) == 0) {
    item.ownerUid = static_cast<int>(ost.st_uid);
    item.originalMode = static_cast<int>(ost.st_mode & 07777 & ~(S_ISUID | S_ISGID));
  }
  if (!threat.originUrl.empty()) {
    item.originUrl = threat.originUrl;
  } else {
    char ob[4096];
    ssize_t on = getxattr(path.c_str(), "user.xdg.origin.url", ob, sizeof(ob) - 1);
    if (on > 0) item.originUrl.assign(ob, static_cast<size_t>(on));
  }
  item.dataPath = dir_ + "/data/" + item.id + ".bin";
  item.metaPath = dir_ + "/meta/" + item.id + ".json";

  if (!moveFile(path, item.dataPath, 0, err)) return std::nullopt;
  if (::geteuid() == 0) (void)::chown(item.dataPath.c_str(), 0, 0);

  if (!saveMeta(item)) {
    std::string ignore;
    moveFile(item.dataPath, path, item.originalMode, &ignore);
    if (err) *err = "cannot write quarantine record";
    return std::nullopt;
  }
  items_.push_back(item);
  return item;
}

bool Quarantine::restore(const std::string& id, std::string* err) {
  std::lock_guard<std::mutex> lock(mu_);
  auto it = std::find_if(items_.begin(), items_.end(), [&](const QuarantineItem& i) { return i.id == id; });
  if (it == items_.end()) {
    if (err) *err = "not found";
    return false;
  }
  std::error_code ec;
  ensureDir(fs::path(it->originalPath).parent_path().string());
  if (fs::exists(fs::symlink_status(it->originalPath, ec))) {
    if (err) *err = "a file already exists at " + it->originalPath;
    return false;
  }
  if (!moveFile(it->dataPath, it->originalPath, it->originalMode, err)) return false;
  if (::geteuid() == 0 && it->ownerUid >= 0) {
    struct stat pst{};
    gid_t gid = 0;
    if (::stat(fs::path(it->originalPath).parent_path().c_str(), &pst) == 0) gid = pst.st_gid;
    (void)::chown(it->originalPath.c_str(), static_cast<uid_t>(it->ownerUid), gid);
    ::chmod(it->originalPath.c_str(), static_cast<mode_t>(it->originalMode));
  }
  fs::remove(it->metaPath, ec);
  items_.erase(it);
  return true;
}

bool Quarantine::remove(const std::string& id, std::string* err) {
  std::lock_guard<std::mutex> lock(mu_);
  auto it = std::find_if(items_.begin(), items_.end(), [&](const QuarantineItem& i) { return i.id == id; });
  if (it == items_.end()) {
    if (err) *err = "not found";
    return false;
  }
  std::error_code ec;
  fs::remove(it->dataPath, ec);
  fs::remove(it->metaPath, ec);
  items_.erase(it);
  return true;
}

std::vector<QuarantineItem> Quarantine::list() const {
  std::lock_guard<std::mutex> lock(mu_);
  return items_;
}

std::optional<QuarantineItem> Quarantine::get(const std::string& id) const {
  std::lock_guard<std::mutex> lock(mu_);
  for (const auto& i : items_) if (i.id == id) return i;
  return std::nullopt;
}

} // namespace oreon
