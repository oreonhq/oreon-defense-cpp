#pragma once
#include <oreon/Types.hpp>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

namespace oreon {

class RuleEngine;
class Quarantine;
class EventLog;

class Scanner {
public:
  using ProgressCb = std::function<void(const ScanProgress&)>;
  using ThreatCb = std::function<void(const Threat&)>;

  Scanner() = default;
  ~Scanner() {
    cancel_ = true;
    if (thr_.joinable()) thr_.join();
  }

  void setRuleEngine(RuleEngine* e) { engine_ = e; }
  void setQuarantine(Quarantine* q) { quarantine_ = q; }
  void setEventLog(EventLog* l) { log_ = l; }
  void setExclusions(const std::vector<std::string>& e) { exclusions_ = e; }
  void setAutoQuarantine(bool v) { autoQuarantine_ = v; }
  void setProgressCb(ProgressCb cb) { progressCb_ = std::move(cb); }
  void setThreatCb(ThreatCb cb) { threatCb_ = std::move(cb); }

  bool start(const std::string& type, const std::vector<std::string>& roots);
  void cancel();
  ScanProgress progress() const;
  bool running() const { return running_; }

private:
  void run(std::string type, std::vector<std::string> roots);
  bool excluded(const std::string& path) const;
  uint64_t countFiles(const std::vector<std::string>& roots) const;

  RuleEngine* engine_{nullptr};
  Quarantine* quarantine_{nullptr};
  EventLog* log_{nullptr};
  std::vector<std::string> exclusions_;
  bool autoQuarantine_{true};
  ProgressCb progressCb_;
  ThreatCb threatCb_;
  std::thread thr_;
  std::atomic<bool> running_{false};
  std::atomic<bool> cancel_{false};
  mutable std::mutex mu_;
  ScanProgress prog_;
};

} // namespace oreon
