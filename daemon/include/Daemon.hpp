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
#include "ClamEngine.hpp"
#include "OnAccessMonitor.hpp"
#include "NetBlocker.hpp"
#include "RuleUpdater.hpp"
#include "GuardMonitor.hpp"
#include "Guard.hpp"
#include "PeerAuth.hpp"
#include "Detection.hpp"
#include <oreon/Types.hpp>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <functional>
#include <vector>
#include <unordered_set>
#include <unordered_map>

namespace oreon {

class Daemon {
public:
  ~Daemon();
  bool init(const std::string& configPath = "");
  int run();
  void requestStop();

private:
  json handleRequest(const Peer& peer, const std::string& method, const json& params);
  json statusJson();
  json engineJson();
  void onFileEvent(const FileEvent& ev);
  void onProcessEvent(const ProcessEvent& ev);
  void handleProcess(const ProcessEvent& ev);
  void onNetworkEvent(const NetworkEntry& ev);
  void onAccessDenied(const std::string& path, pid_t pid, bool exec, const Detection& d, bool timedOut);
  void onThreat(Threat t, bool autoQuarantine);
  void refreshStatus();
  void applyProtection();
  void applyGuards();
  void onGuardAlert(const GuardMonitor::Alert& a);
  void applyRules();
  void broadcastEngine();
  void loadAllowList();
  void saveAllowList();
  bool allowed(const std::string& path);
  std::vector<std::string> quickScanRoots() const;
  std::vector<std::string> fullScanRoots() const;
  std::vector<std::string> onAccessExclusions() const;
  std::string newThreatId();

  Detection detect(const std::string& path);
  Detection detectFd(int fd, const std::string& path, const ScanContext& ctx = {});
  Detection execGate(const std::string& path, pid_t pid);
  Detection fromClam(const ClamEngine::Result& r) const;
  Detection fromRule(const MatchResult& m) const;
  bool exeClean(const std::string& exe, Detection& d);
  Threat threatFrom(const Detection& d, const std::string& path);
  bool killPid(int pid, const std::string& expectExe, std::string* err);

  void post(std::function<void()> fn);
  void workerLoop();

  Config config_;
  EventLog log_;
  RuleEngine engine_;
  ClamEngine clam_;
  Quarantine quarantine_;
  FileMonitor fileMon_;
  OnAccessMonitor onAccess_;
  ProcessMonitor procMon_;
  NetworkMonitor netMon_;
  NetBlocker netBlock_;
  RuleUpdater updater_;
  GuardMonitor guard_;
  guard::RansomTracker ransom_;
  PeerAuth auth_;
  Scanner scanner_;
  SocketServer server_;

  std::atomic<bool> stop_{false};
  mutable std::mutex mu_;
  ProtectionState status_;
  std::vector<Threat> threats_;
  std::unordered_set<std::string> allowedPaths_;
  std::unordered_map<std::string, int64_t> recentFileHits_;
  std::string onAccessMode_{"off"};
  std::string onAccessError_;
  std::string netBlockError_;
  int64_t lastManualUpdate_{0};
  int64_t nextRulesCheck_{0};

  std::mutex exeMu_;
  std::unordered_map<std::string, int64_t> exeClean_;

  std::mutex wqMu_;
  std::condition_variable wqCv_;
  std::deque<std::function<void()>> wq_;
  std::thread worker_;
  std::atomic<uint64_t> threatSeq_{0};
};

} // namespace oreon
