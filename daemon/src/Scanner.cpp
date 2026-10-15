#include "Scanner.hpp"
#include "RuleEngine.hpp"
#include "Quarantine.hpp"
#include "EventLog.hpp"
#include <oreon/Hash.hpp>
#include <algorithm>
#include <filesystem>
#include <iostream>

namespace oreon {
namespace fs = std::filesystem;

bool Scanner::start(const std::string& type, const std::vector<std::string>& roots) {
  if (running_) return false;
  // Previous finished scan leaves a joinable thread; must join before reassigning.
  if (thr_.joinable()) thr_.join();
  cancel_ = false;
  running_ = true;
  {
    std::lock_guard<std::mutex> lock(mu_);
    prog_ = ScanProgress{};
    prog_.scanId = "scan-" + std::to_string(nowEpoch());
    prog_.type = type;
    prog_.running = true;
  }
  thr_ = std::thread([this, type, roots] { run(type, roots); });
  return true;
}

void Scanner::cancel() { cancel_ = true; }

ScanProgress Scanner::progress() const {
  std::lock_guard<std::mutex> lock(mu_);
  return prog_;
}

bool Scanner::excluded(const std::string& path) const {
  for (const auto& e : exclusions_) {
    if (e.empty()) continue;
    if (path == e || path.find(e + "/") == 0) return true;
  }
  // Always skip virtual fs and our own state dirs (even if config omitted them).
  if (path.find("/proc") == 0 || path.find("/sys") == 0 || path.find("/dev") == 0)
    return true;
  if (path.find("/oreon-defense/") != std::string::npos) return true;
  return false;
}

uint64_t Scanner::countFiles(const std::vector<std::string>& roots) const {
  uint64_t n = 0;
  for (const auto& root : roots) {
    std::error_code ec;
    if (!fs::exists(root, ec)) continue;
    if (fs::is_regular_file(root, ec)) { ++n; continue; }
    for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
      if (ec) { ec.clear(); continue; }
      if (excluded(it->path().string())) {
        it.disable_recursion_pending();
        continue;
      }
      if (it->is_regular_file(ec)) ++n;
      if (n > 200000) return n;
    }
  }
  return n;
}

void Scanner::run(std::string type, std::vector<std::string> roots) {
  if (log_) log_->info("scan", "started " + type + " scan");

  uint64_t total = countFiles(roots);
  {
    std::lock_guard<std::mutex> lock(mu_);
    prog_.filesTotal = total;
  }

  auto scanOne = [&](const fs::path& p) {
    if (cancel_) return;
    if (!p.has_filename()) return;
    std::string path = p.string();
    if (excluded(path)) return;

    {
      std::lock_guard<std::mutex> lock(mu_);
      prog_.filesScanned++;
      prog_.currentPath = path;
      if (progressCb_ && (prog_.filesScanned % 25 == 0)) progressCb_(prog_);
    }

    if (!engine_ && !detect_) return;
    // skip huge files
    std::error_code ec;
    auto sz = fs::file_size(p, ec);
    if (ec || sz > 100ull * 1024 * 1024) return;

    Detection d;
    if (detect_) {
      d = detect_(path);
    } else {
      auto m = engine_->matchFile(path);
      if (m.matched) {
        d.matched = true;
        d.name = m.rule.name;
        d.ruleId = m.rule.id;
        d.detail = m.detail;
        d.description = m.rule.description;
        d.severity = m.rule.severity;
        d.engine = "rules";
        if (m.heuristic) {
          d.heuristic = true;
          d.severity = std::min(d.severity, Severity::Low);
          d.kill = false;
        }
      }
    }
    if (!d.matched) return;

    Threat t;
    t.id = "thr-" + std::to_string(nowEpoch()) + "-" + std::to_string(prog_.filesScanned);
    t.name = d.name;
    t.path = path;
    t.ruleId = d.ruleId;
    t.description = d.description + " [" + d.detail + "]";
    t.severity = d.severity;
    t.heuristic = d.heuristic;
    t.engine = d.engine;
    t.sha256 = sha256File(path);
    t.timestamp = nowEpoch();
    t.action = ThreatAction::Detected;

    if (autoQuarantine_ && quarantine_ && t.severity >= Severity::High) {
      std::string qerr;
      auto q = quarantine_->quarantineFile(path, t, &qerr);
      if (q) {
        t.action = ThreatAction::Quarantined;
        t.quarantineId = q->id;
      } else if (log_) {
        log_->warn("scan", "quarantine failed: " + qerr, path);
      }
    }

    {
      std::lock_guard<std::mutex> lock(mu_);
      prog_.threatsFound++;
    }
    if (threatCb_) threatCb_(t);
  };

  for (const auto& root : roots) {
    if (cancel_) break;
    std::error_code ec;
    if (!fs::exists(root, ec)) continue;
    if (fs::is_regular_file(root, ec)) {
      scanOne(root);
      continue;
    }
    for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
      if (cancel_) break;
      if (ec) { ec.clear(); continue; }
      if (excluded(it->path().string())) {
        it.disable_recursion_pending();
        continue;
      }
      if (it->is_regular_file(ec)) scanOne(it->path());
    }
  }

  {
    std::lock_guard<std::mutex> lock(mu_);
    prog_.running = false;
    prog_.cancelled = cancel_;
    prog_.currentPath.clear();
    if (progressCb_) progressCb_(prog_);
  }
  if (log_) {
    if (cancel_) log_->info("scan", "scan cancelled");
    else log_->info("scan", "scan finished threats=" + std::to_string(prog_.threatsFound));
  }
  running_ = false;
}

} // namespace oreon
