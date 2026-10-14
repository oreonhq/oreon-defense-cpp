#pragma once
#include <oreon/Types.hpp>
#include <mutex>
#include <vector>
#include <fstream>
#include <functional>

namespace oreon {

class EventLog {
public:
  using Listener = std::function<void(const LogEvent&)>;

  void open(const std::string& path);
  void append(const LogEvent& e);
  void info(const std::string& cat, const std::string& msg, const std::string& path = "");
  void warn(const std::string& cat, const std::string& msg, const std::string& path = "");
  void alert(const std::string& cat, Severity sev, const std::string& msg, const std::string& path = "");
  std::vector<LogEvent> query(const std::string& search, size_t limit = 500) const;
  void addListener(Listener l);

private:
  mutable std::mutex mu_;
  std::string path_;
  std::vector<LogEvent> recent_;
  std::vector<Listener> listeners_;
  static std::string nextId();
};

} // namespace oreon
