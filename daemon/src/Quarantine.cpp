#include "Quarantine.hpp"
#include <oreon/JsonUtil.hpp>
#include <oreon/Hash.hpp>
#include <oreon/Paths.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <random>

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

void Quarantine::saveMeta(const QuarantineItem& item) const {
  std::ofstream out(item.metaPath);
  if (out) out << quarantineToJson(item).dump(2) << "\n";
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
      if (!item.id.empty()) items_.push_back(item);
    } catch (...) {}
  }
}

std::optional<QuarantineItem> Quarantine::quarantineFile(const std::string& path, const Threat& threat) {
  std::lock_guard<std::mutex> lock(mu_);
  if (!fs::exists(path)) return std::nullopt;
  if (!dir_.empty() && (path == dir_ || path.find(dir_ + "/") == 0))
    return std::nullopt;

  QuarantineItem item;
  item.id = makeId();
  item.originalPath = path;
  item.threatName = threat.name.empty() ? "Unknown threat" : threat.name;
  item.sha256 = threat.sha256.empty() ? sha256File(path) : threat.sha256;
  item.severity = threat.severity;
  item.quarantinedAt = nowEpoch();
  item.dataPath = dir_ + "/data/" + item.id + ".bin";
  item.metaPath = dir_ + "/meta/" + item.id + ".json";

  std::error_code ec;
  fs::rename(path, item.dataPath, ec);
  if (ec) {
    fs::copy_file(path, item.dataPath, fs::copy_options::overwrite_existing, ec);
    if (ec) return std::nullopt;
    fs::remove(path, ec);
  }

  saveMeta(item);
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
  fs::rename(it->dataPath, it->originalPath, ec);
  if (ec) {
    fs::copy_file(it->dataPath, it->originalPath, fs::copy_options::overwrite_existing, ec);
    if (ec) {
      if (err) *err = ec.message();
      return false;
    }
    fs::remove(it->dataPath, ec);
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
