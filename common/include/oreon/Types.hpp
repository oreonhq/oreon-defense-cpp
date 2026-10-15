#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace oreon {

enum class Severity : int {
  Info = 0,
  Low = 1,
  Medium = 2,
  High = 3,
  Critical = 4
};

inline const char* severityToString(Severity s) {
  switch (s) {
    case Severity::Info: return "info";
    case Severity::Low: return "low";
    case Severity::Medium: return "medium";
    case Severity::High: return "high";
    case Severity::Critical: return "critical";
  }
  return "info";
}

inline Severity severityFromString(const std::string& s) {
  if (s == "critical") return Severity::Critical;
  if (s == "high") return Severity::High;
  if (s == "medium") return Severity::Medium;
  if (s == "low") return Severity::Low;
  return Severity::Info;
}

enum class ThreatAction {
  Detected,
  Quarantined,
  Allowed,
  Restored,
  Deleted,
  Blocked,
  Killed
};

struct Threat {
  std::string id;
  std::string name;
  std::string path;
  std::string ruleId;
  std::string description;
  Severity severity{Severity::Medium};
  std::string sha256;
  int64_t timestamp{0};
  ThreatAction action{ThreatAction::Detected};
  std::string quarantineId;
  std::string engine;
  std::string kind{"file"};
  int pid{0};
  std::string remoteAddr;
  std::string originUrl;
  bool heuristic{false};
};

struct ScanProgress {
  std::string scanId;
  std::string type;
  uint64_t filesScanned{0};
  uint64_t filesTotal{0};
  uint64_t threatsFound{0};
  std::string currentPath;
  bool running{false};
  bool cancelled{false};
};

struct NetworkEntry {
  std::string proto;
  std::string localAddr;
  std::string remoteAddr;
  std::string state;
  int pid{0};
  std::string process;
  std::string risk;
};

struct ProcessEvent {
  int pid{0};
  int ppid{0};
  std::string name;
  std::string cmdline;
  std::vector<std::string> argv;
  std::string exe;
  int64_t timestamp{0};
  bool suspicious{false};
  std::string reason;
  std::string ruleId;
  bool kill{false};
  Severity severity{Severity::High};
};

struct FileEvent {
  std::string path;
  std::string op;
  int64_t timestamp{0};
};

struct LogEvent {
  std::string id;
  int64_t timestamp{0};
  std::string category;
  Severity severity{Severity::Info};
  std::string message;
  std::string path;
};

struct ProtectionState {
  bool fileRealtime{true};
  bool processWatch{true};
  bool networkWatch{true};
  bool protectedStatus{true};
  std::string statusText{"Protected"};
  int64_t lastScan{0};
  uint64_t threatCount{0};
  uint64_t quarantineCount{0};
};

struct QuarantineItem {
  std::string id;
  std::string originalPath;
  std::string threatName;
  std::string sha256;
  Severity severity{Severity::Medium};
  int64_t quarantinedAt{0};
  std::string metaPath;
  std::string dataPath;
  int ownerUid{-1};
  std::string originUrl;
  int originalMode{0600};
};

struct DaemonConfig {
  std::vector<std::string> watchPaths;
  std::vector<std::string> exclusions;
  std::string quarantineDir;
  std::string dataDir;
  std::string rulesPath;
  std::string socketPath;
  std::string logPath;
  bool fileRealtime{true};
  bool processWatch{true};
  bool networkWatch{true};
  int networkPollMs{2000};
  int processPollMs{1500};
  int scheduleHour{-1};
  int scheduleMinute{0};
  std::string scheduleType{"none"};

  bool clamavEnabled{true};
  std::string clamavDbDir{"/var/lib/clamav"};
  int clamavMaxFileMb{100};

  bool onAccessBlocking{true};
  bool onAccessScanOpen{true};
  std::vector<std::string> onAccessPaths;
  int onAccessTimeoutMs{3000};
  int onAccessMaxFileMb{32};

  bool killMalicious{true};

  bool networkBlocking{true};

  bool rulesAutoUpdate{true};
  std::string rulesUrl{"https://od-rules.oreonhq.com"};
  int rulesUpdateHours{6};
  std::string rulesPublicKey;

  int fileScanMaxFileMb{200};

  bool ransomShield{true};
  bool execProtection{true};
  bool persistenceGuard{true};
  bool revShellWatch{true};
  bool privEscWatch{true};
  std::vector<std::string> execAllowList;

  std::vector<std::string> adminGroups{"wheel"};
};

inline int64_t nowEpoch() {
  using namespace std::chrono;
  return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

} // namespace oreon
