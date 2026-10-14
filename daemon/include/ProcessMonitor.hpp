#pragma once
#include <oreon/Types.hpp>
#include <functional>
#include <thread>
#include <atomic>
#include <unordered_set>
#include <mutex>

namespace oreon {

class RuleEngine;

class ProcessMonitor {
public:
  using Callback = std::function<void(const ProcessEvent&)>;

  void setIntervalMs(int ms) { intervalMs_ = ms; }
  void setRuleEngine(RuleEngine* eng) { engine_ = eng; }
  void setCallback(Callback cb) { cb_ = std::move(cb); }
  bool start();
  void stop();
  bool running() const { return running_; }

private:
  void loop();
  void scanOnce();

  int intervalMs_{1500};
  RuleEngine* engine_{nullptr};
  Callback cb_;
  std::thread thr_;
  std::atomic<bool> running_{false};
  std::unordered_set<int> seen_;
  std::mutex mu_;
};

} // namespace oreon
