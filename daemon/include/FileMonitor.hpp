#pragma once
#include <oreon/Types.hpp>
#include <functional>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <sys/inotify.h>

namespace oreon {

class FileMonitor {
public:
  using Callback = std::function<void(const FileEvent&)>;

  FileMonitor();
  ~FileMonitor();

  void setPaths(const std::vector<std::string>& paths);
  void setExclusions(const std::vector<std::string>& excl);
  void setCallback(Callback cb);
  bool start();
  void stop();
  bool running() const { return running_; }

private:
  void loop();
  void addWatchRecursive(const std::string& path, int depth = 0);
  bool isExcluded(const std::string& path) const;

  std::vector<std::string> paths_;
  std::vector<std::string> exclusions_;
  Callback cb_;
  std::thread thr_;
  std::atomic<bool> running_{false};
  int fd_{-1};
  std::mutex mu_;
  std::unordered_map<int, std::string> wdToPath_;
};

} // namespace oreon
