#pragma once
#include "Detection.hpp"
#include <functional>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <memory>
#include <unordered_map>
#include <list>
#include <sys/types.h>

namespace oreon {

class OnAccessMonitor {
public:
  using ScanFn = std::function<Detection(int fd, const std::string& path, pid_t pid, bool exec)>;
  using DenyFn = std::function<void(const std::string& path, pid_t pid, bool exec,
                                    const Detection& d, bool timedOut)>;

  OnAccessMonitor();
  ~OnAccessMonitor();

  void setPaths(const std::vector<std::string>& p);
  void setExclusions(const std::vector<std::string>& e);
  void setScanOpen(bool v) { scanOpen_ = v; }
  void setTimeoutMs(int ms) { timeoutMs_ = ms > 100 ? ms : 100; }
  void setMaxFileBytes(uint64_t b) { maxBytes_ = b; }
  void setScanFn(ScanFn f) { scan_ = std::move(f); }
  void setDenyFn(DenyFn f) { deny_ = std::move(f); }

  bool start(std::string* err = nullptr);
  void stop();
  bool running() const { return running_; }
  void clearCache();

  struct Stats {
    uint64_t events{0}, scanned{0}, denied{0}, timeouts{0}, cacheHits{0};
    std::string markMode;
    bool execPerm{false};
    std::vector<std::string> marked;
  };
  Stats stats() const;

private:
  struct Job {
    int fd{-1};
    pid_t pid{0};
    bool exec{false};
    std::string path;
    std::string key;
    uint64_t size{0};
    int64_t deadlineMs{0};
    std::atomic<bool> answered{false};
  };

  void readerLoop();
  void workerLoop();
  void watchdogLoop();
  void respond(int fd, bool allow);
  void answer(const std::shared_ptr<Job>& j, bool allow);
  void addIgnoreMark(int fd);
  bool inScope(const std::string& path) const;
  bool cacheHit(const std::string& key);
  void cachePut(const std::string& key);

  std::vector<std::string> paths_;
  std::vector<std::string> exclusions_;
  bool scanOpen_{true};
  int timeoutMs_{3000};
  uint64_t maxBytes_{32ull * 1024 * 1024};
  ScanFn scan_;
  DenyFn deny_;

  int fan_{-1};
  int wakeFd_{-1};
  std::atomic<bool> running_{false};
  std::thread reader_, watchdog_;
  std::vector<std::thread> workers_;

  std::mutex qmu_;
  std::condition_variable qcv_;
  std::deque<std::shared_ptr<Job>> queue_;
  std::mutex pmu_;
  std::list<std::shared_ptr<Job>> pending_;
  std::mutex wmu_;

  mutable std::mutex cmu_;
  std::unordered_map<std::string, int64_t> cache_;
  std::atomic<uint64_t> ignoreMarks_{0};

  mutable std::mutex smu_;
  Stats stats_;
  pid_t self_{0};
};

}
