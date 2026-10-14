#pragma once
#include "Config.hpp"
#include "EventLog.hpp"
#include "RuleEngine.hpp"
#include "Quarantine.hpp"
#include "FileMonitor.hpp"
#include "ProcessMonitor.hpp"
#include "NetworkMonitor.hpp"
#include "Scanner.hpp"
#include "SocketServer.hpp"
#include <oreon/Types.hpp>
#include <atomic>
#include <mutex>
#include <vector>
#include <unordered_set>
#include <unordered_map>

namespace oreon {

class Daemon {
public:
  bool init(const std::string& configPath = "");
  int run();
  void requestStop();

private:
  json handleRequest(const std::string& method, const json& params);
  void onFileEvent(const FileEvent& ev);
  void onProcessEvent(const ProcessEvent& ev);
  void onNetworkEvent(const NetworkEntry& ev);
  void onThreat(Threat t, bool autoQuarantine);
  void refreshStatus();
  void applyProtection();
  std::vector<std::string> quickScanRoots() const;
  std::vector<std::string> fullScanRoots() const;

  Config config_;
  EventLog log_;
  RuleEngine engine_;
  Quarantine quarantine_;
  FileMonitor fileMon_;
  ProcessMonitor procMon_;
  NetworkMonitor netMon_;
  Scanner scanner_;
  SocketServer server_;

  std::atomic<bool> stop_{false};
  mutable std::mutex mu_;
  ProtectionState status_;
  std::vector<Threat> threats_;
  std::unordered_set<std::string> allowedPaths_;
  std::unordered_map<std::string, int64_t> recentFileHits_;
};

} // namespace oreon
