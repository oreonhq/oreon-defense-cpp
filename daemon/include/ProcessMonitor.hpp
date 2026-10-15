#pragma once
#include <oreon/Types.hpp>
#include <functional>
#include <thread>
#include <atomic>
#include <unordered_set>
#include <mutex>
#include <string>

namespace oreon {

class RuleEngine;

class ProcessMonitor {
public:
  using Callback = std::function<void(const ProcessEvent&)>;

  void setIntervalMs(int ms) { intervalMs_ = ms; }
  void setRuleEngine(RuleEngine* eng) { engine_ = eng; }
  void setCallback(Callback cb) { cb_ = std::move(cb); }
  void setPreferNetlink(bool v) { preferNetlink_ = v; }
  void setModeCallback(std::function<void(const std::string&, const std::string&)> cb) { modeCb_ = std::move(cb); }
  bool start();
  void stop();
  bool running() const { return running_; }
  std::string mode() const;
  std::string lastError() const;

  static bool readProcess(int pid, ProcessEvent& pe);
  static bool consistent(const ProcessEvent& pe);

private:
  void pollLoop();
  void netlinkLoop();
  void scanOnce();
  void handlePid(int pid);
  bool openNetlink(std::string* err);

  int intervalMs_{1500};
  bool preferNetlink_{true};
  RuleEngine* engine_{nullptr};
  Callback cb_;
  std::function<void(const std::string&, const std::string&)> modeCb_;
  std::thread thr_;
  std::atomic<bool> running_{false};
  std::unordered_set<int> seen_;
  mutable std::mutex mu_;
  int nl_{-1};
  std::string mode_{"off"};
  std::string lastError_;
};

} // namespace oreon
