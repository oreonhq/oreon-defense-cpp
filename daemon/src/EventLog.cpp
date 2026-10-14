#include "EventLog.hpp"
#include <oreon/JsonUtil.hpp>
#include <oreon/Paths.hpp>
#include <filesystem>
#include <atomic>
#include <iostream>
#include <fstream>

namespace oreon {
namespace fs = std::filesystem;

std::string EventLog::nextId() {
  static std::atomic<uint64_t> n{0};
  return "evt-" + std::to_string(nowEpoch()) + "-" + std::to_string(++n);
}

void EventLog::open(const std::string& path) {
  std::lock_guard<std::mutex> lock(mu_);
  path_ = path;
  ensureDir(fs::path(path).parent_path().string());
}

void EventLog::addListener(Listener l) {
  std::lock_guard<std::mutex> lock(mu_);
  listeners_.push_back(std::move(l));
}

void EventLog::append(const LogEvent& e) {
  LogEvent copy = e;
  if (copy.id.empty()) copy.id = nextId();
  if (copy.timestamp == 0) copy.timestamp = nowEpoch();

  std::vector<Listener> ls;
  {
    std::lock_guard<std::mutex> lock(mu_);
    recent_.push_back(copy);
    if (recent_.size() > 5000)
      recent_.erase(recent_.begin(), recent_.begin() + 1000);
    if (!path_.empty()) {
      std::ofstream out(path_, std::ios::app);
      if (out) out << logToJson(copy).dump() << "\n";
    }
    std::cerr << "[oreon-defense] " << copy.category << " "
              << severityToString(copy.severity) << " " << copy.message;
    if (!copy.path.empty()) std::cerr << " path=" << copy.path;
    std::cerr << "\n";
    ls = listeners_;
  }
  for (auto& l : ls) l(copy);
}

void EventLog::info(const std::string& cat, const std::string& msg, const std::string& path) {
  LogEvent e;
  e.category = cat;
  e.severity = Severity::Info;
  e.message = msg;
  e.path = path;
  append(e);
}

void EventLog::warn(const std::string& cat, const std::string& msg, const std::string& path) {
  LogEvent e;
  e.category = cat;
  e.severity = Severity::Medium;
  e.message = msg;
  e.path = path;
  append(e);
}

void EventLog::alert(const std::string& cat, Severity sev, const std::string& msg, const std::string& path) {
  LogEvent e;
  e.category = cat;
  e.severity = sev;
  e.message = msg;
  e.path = path;
  append(e);
}

std::vector<LogEvent> EventLog::query(const std::string& search, size_t limit) const {
  std::lock_guard<std::mutex> lock(mu_);
  std::vector<LogEvent> out;
  for (auto it = recent_.rbegin(); it != recent_.rend() && out.size() < limit; ++it) {
    if (search.empty() ||
        it->message.find(search) != std::string::npos ||
        it->path.find(search) != std::string::npos ||
        it->category.find(search) != std::string::npos) {
      out.push_back(*it);
    }
  }
  return out;
}

} // namespace oreon
