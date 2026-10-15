#pragma once
#include "SystemTrust.hpp"
#include <atomic>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace oreon {

class WriteTracker {
public:
  struct Write {
    std::string path;
    std::string dir;
    int64_t atMs{0};
    trust::ActorVerdict actor;
  };

  bool start(const std::vector<std::string>& dirs);
  void stop();
  bool running() const { return running_; }
  std::string mode() const { return mode_; }

  bool lookup(const std::string& path, int64_t windowMs, Write& out) const;

  void record(const std::string& path, pid_t pid);
  void recordVerdict(const std::string& path, const trust::ActorVerdict& v);

private:
  void loop();
  void handleBuffer(const char* buf, ssize_t len);

  int fd_{-1};
  bool fidMode_{false};
  std::atomic<bool> running_{false};
  std::string mode_{"off"};
  std::thread thr_;
  mutable std::mutex mu_;
  std::deque<Write> recent_;
  std::map<std::string, std::string> handles_;
};

}
