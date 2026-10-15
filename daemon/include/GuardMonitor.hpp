#pragma once
#include "Guard.hpp"
#include "WriteTracker.hpp"
#include <functional>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <sys/inotify.h>

namespace oreon {

class GuardMonitor {
public:
  struct Alert {
    std::string category;
    Severity severity{Severity::High};
    std::string title;
    std::string message;
    std::string path;
    std::string detail;
    bool kill{false};
    int pid{0};
    std::string reasons;
  };
  using InfoCallback = std::function<void(const std::string& path, const std::string& reasons)>;
  void setInfoCallback(InfoCallback cb) { info_ = std::move(cb); }
  std::string attributionMode() const { return tracker_.mode(); }
  using Callback = std::function<void(const Alert&)>;

  void setCallback(Callback cb) { cb_ = std::move(cb); }
  void setRansomShield(bool v) { ransom_ = v; }
  void setPersistenceGuard(bool v) { persistence_ = v; }
  void setPrivEscWatch(bool v) { privesc_ = v; }
  void setExclusions(const std::vector<std::string>& e) { exclusions_ = e; }

  bool start();
  void stop();
  bool running() const { return running_; }

  static const char* canaryName() { return ".oreon-defense-keepsafe"; }

  std::vector<std::string> placeCanaries();

private:
  void loop();
  void addWatch(const std::string& path, bool isCanary);
  std::vector<std::string> userHomes() const;
  void seedPersistenceSnapshots();
  void onCanaryEvent(const std::string& path, uint32_t mask);
  void onPersistenceEvent(const std::string& path);
  bool excluded(const std::string& path) const;

  void report(const std::string& path, const std::string& before, const std::string& after);
  Callback cb_;
  InfoCallback info_;
  WriteTracker tracker_;
  bool ransom_{true}, persistence_{true}, privesc_{true};
  std::vector<std::string> exclusions_;
  std::vector<std::string> canaries_;
  std::vector<std::string> persistPaths_;
  std::unordered_map<std::string, std::string> snapshots_;
  std::thread thr_;
  std::atomic<bool> running_{false};
  int fd_{-1};
  std::mutex mu_;
  std::unordered_map<int, std::string> wd_;
  std::unordered_map<int, bool> wdCanary_;
};

}
