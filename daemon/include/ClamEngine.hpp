#pragma once
#include <string>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <thread>
#include <functional>
#include <cstdint>

struct cl_engine;
struct cl_stat;

namespace oreon {

class ClamEngine {
public:
  struct Status {
    bool available{false};
    bool loading{false};
    std::string dbDir;
    unsigned int signatures{0};
    unsigned int dailyVersion{0};
    unsigned int mainVersion{0};
    int64_t dbTime{0};
    int64_t loadedAt{0};
    std::string libVersion;
    std::string error;
  };

  struct Result {
    bool infected{false};
    bool error{false};
    std::string virusName;
    std::string message;
  };

  using ReloadCb = std::function<void(const Status&)>;

  ClamEngine();
  ~ClamEngine();

  void setDbDir(const std::string& dir) { dbDir_ = dir; }
  void setMaxFileMb(int mb) { maxFileMb_ = mb; }
  void setReloadCallback(ReloadCb cb) { reloadCb_ = std::move(cb); }

  void loadAsync();
  bool loadNow();
  bool checkForUpdates();
  void shutdown();

  Result scanFd(int fd, const std::string& displayName) const;
  Result scanFile(const std::string& path) const;
  Status status() const;
  bool ready() const;

private:
  struct Holder;
  bool doLoad();

  std::string dbDir_{"/var/lib/clamav"};
  int maxFileMb_{100};
  ReloadCb reloadCb_;

  mutable std::shared_mutex engMu_;
  std::shared_ptr<Holder> engine_;

  mutable std::mutex stMu_;
  Status status_;
  cl_stat* dbstat_{nullptr};

  std::mutex loadMu_;
  std::thread loader_;
  std::atomic<bool> loading_{false};
  std::atomic<bool> stopping_{false};
};

}
