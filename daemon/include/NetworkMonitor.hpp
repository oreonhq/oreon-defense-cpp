#pragma once
#include <oreon/Types.hpp>
#include <functional>
#include <thread>
#include <atomic>
#include <vector>
#include <mutex>
#include <string>
#include <unordered_set>

namespace oreon {

class NetworkMonitor {
public:
  using Callback = std::function<void(const NetworkEntry&)>;

  void setIntervalMs(int ms) { intervalMs_ = ms; }
  void setCallback(Callback cb) { cb_ = std::move(cb); }
  bool start();
  void stop();
  bool running() const { return running_; }
  std::vector<NetworkEntry> snapshot() const;

private:
  void loop();
  std::vector<NetworkEntry> poll();
  static std::string riskHint(const NetworkEntry& e);

  int intervalMs_{2000};
  Callback cb_;
  std::thread thr_;
  std::atomic<bool> running_{false};
  mutable std::mutex mu_;
  std::vector<NetworkEntry> last_;
  std::unordered_set<std::string> seenKeys_;
};

} // namespace oreon
