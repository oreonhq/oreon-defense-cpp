#include "Config.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>

namespace oreon {
using json = nlohmann::json;

void Config::applyDefaults() {
  cfg_.dataDir = defaultDataDir();
  cfg_.quarantineDir = defaultQuarantineDir();
  cfg_.socketPath = defaultSocketPath();
  cfg_.logPath = defaultLogPath();
  cfg_.rulesPath = defaultRulesPath();
  cfg_.fileRealtime = true;
  cfg_.processWatch = true;
  cfg_.networkWatch = true;
  cfg_.networkPollMs = 2000;
  cfg_.processPollMs = 1500;
  cfg_.scheduleHour = -1;
  cfg_.scheduleMinute = 0;
  cfg_.scheduleType = "none";

  std::string home = homeDir();
  if (isRoot()) {
    cfg_.watchPaths = {"/home", "/tmp"};
    cfg_.onAccessPaths = {"/home", "/root", "/tmp", "/var/tmp", "/dev/shm"};
  } else {
    cfg_.watchPaths = {home + "/Downloads", home + "/Desktop", home + "/Documents", "/tmp"};
    cfg_.onAccessPaths = {home, "/tmp"};
  }
  cfg_.exclusions = {
    home + "/.cache",
    home + "/.local/share/oreon-defense",
    "/var/lib/oreon-defense",
    "/proc",
    "/sys",
    "/dev",
    "/run"
  };
  cfg_.clamavEnabled = true;
  cfg_.clamavDbDir = "/var/lib/clamav";
  cfg_.clamavMaxFileMb = 100;
  cfg_.onAccessBlocking = true;
  cfg_.onAccessScanOpen = true;
  cfg_.onAccessTimeoutMs = 3000;
  cfg_.onAccessMaxFileMb = 32;
  cfg_.killMalicious = true;
  cfg_.networkBlocking = true;
  cfg_.rulesAutoUpdate = true;
  cfg_.rulesUrl = "https://od-rules.oreonhq.com";
  cfg_.rulesUpdateHours = 6;
  cfg_.rulesPublicKey = defaultPublicKeyPath();
  cfg_.fileScanMaxFileMb = 200;
  cfg_.ransomShield = true;
  cfg_.execProtection = true;
  cfg_.persistenceGuard = true;
  cfg_.revShellWatch = true;
  cfg_.privEscWatch = true;
  cfg_.execAllowList = {};
  cfg_.adminGroups = {"wheel"};
}

template <typename T>
static void take(const json& j, const char* key, T& dst) {
  if (!j.contains(key)) return;
  try {
    dst = j.at(key).get<T>();
  } catch (const std::exception& e) {
    std::cerr << "config: ignoring bad value for " << key << ": " << e.what() << "\n";
  }
}

static void clampInt(int& v, int lo, int hi) {
  if (v < lo) v = lo;
  if (v > hi) v = hi;
}

bool Config::load(const std::string& path) {
  applyDefaults();
  path_ = path.empty() ? (defaultConfigDir() + "/config.json") : path;
  ensureDir(fs::path(path_).parent_path().string());
  ensureDir(cfg_.dataDir);
  ensureDir(cfg_.quarantineDir);
  ensureDir(fs::path(cfg_.socketPath).parent_path().string());
  ensureDir(fs::path(cfg_.rulesPath).parent_path().string());

  std::ifstream in(path_);
  if (!in) {
    save(path_);
    return true;
  }
  json j;
  try {
    in >> j;
  } catch (const std::exception& e) {
    std::cerr << "config parse error, using defaults: " << e.what() << "\n";
    return true;
  }
  if (!j.is_object()) return true;
  take(j, "watchPaths", cfg_.watchPaths);
  take(j, "exclusions", cfg_.exclusions);
  take(j, "quarantineDir", cfg_.quarantineDir);
  take(j, "dataDir", cfg_.dataDir);
  take(j, "rulesPath", cfg_.rulesPath);
  take(j, "socketPath", cfg_.socketPath);
  take(j, "logPath", cfg_.logPath);
  take(j, "fileRealtime", cfg_.fileRealtime);
  take(j, "processWatch", cfg_.processWatch);
  take(j, "networkWatch", cfg_.networkWatch);
  take(j, "networkPollMs", cfg_.networkPollMs);
  take(j, "processPollMs", cfg_.processPollMs);
  take(j, "scheduleHour", cfg_.scheduleHour);
  take(j, "scheduleMinute", cfg_.scheduleMinute);
  take(j, "scheduleType", cfg_.scheduleType);
  take(j, "clamavEnabled", cfg_.clamavEnabled);
  take(j, "clamavDbDir", cfg_.clamavDbDir);
  take(j, "clamavMaxFileMb", cfg_.clamavMaxFileMb);
  take(j, "onAccessBlocking", cfg_.onAccessBlocking);
  take(j, "onAccessScanOpen", cfg_.onAccessScanOpen);
  take(j, "onAccessPaths", cfg_.onAccessPaths);
  take(j, "onAccessTimeoutMs", cfg_.onAccessTimeoutMs);
  take(j, "onAccessMaxFileMb", cfg_.onAccessMaxFileMb);
  take(j, "killMalicious", cfg_.killMalicious);
  take(j, "networkBlocking", cfg_.networkBlocking);
  take(j, "rulesAutoUpdate", cfg_.rulesAutoUpdate);
  take(j, "rulesUrl", cfg_.rulesUrl);
  take(j, "rulesUpdateHours", cfg_.rulesUpdateHours);
  take(j, "rulesPublicKey", cfg_.rulesPublicKey);
  take(j, "fileScanMaxFileMb", cfg_.fileScanMaxFileMb);
  take(j, "ransomShield", cfg_.ransomShield);
  take(j, "execProtection", cfg_.execProtection);
  take(j, "persistenceGuard", cfg_.persistenceGuard);
  take(j, "revShellWatch", cfg_.revShellWatch);
  take(j, "privEscWatch", cfg_.privEscWatch);
  take(j, "execAllowList", cfg_.execAllowList);
  take(j, "adminGroups", cfg_.adminGroups);
  clampInt(cfg_.networkPollMs, 500, 60000);
  clampInt(cfg_.processPollMs, 200, 60000);
  clampInt(cfg_.onAccessTimeoutMs, 200, 30000);
  clampInt(cfg_.onAccessMaxFileMb, 1, 1024);
  clampInt(cfg_.clamavMaxFileMb, 1, 2048);
  clampInt(cfg_.fileScanMaxFileMb, 1, 4096);
  clampInt(cfg_.rulesUpdateHours, 1, 24 * 7);
  if (cfg_.rulesPublicKey.empty()) cfg_.rulesPublicKey = defaultPublicKeyPath();
  return true;
}

bool Config::save(const std::string& path) const {
  auto p = path.empty() ? path_ : path;
  if (p.empty()) p = defaultConfigDir() + "/config.json";
  ensureDir(fs::path(p).parent_path().string());
  json j{
    {"watchPaths", cfg_.watchPaths},
    {"exclusions", cfg_.exclusions},
    {"quarantineDir", cfg_.quarantineDir},
    {"dataDir", cfg_.dataDir},
    {"rulesPath", cfg_.rulesPath},
    {"socketPath", cfg_.socketPath},
    {"logPath", cfg_.logPath},
    {"fileRealtime", cfg_.fileRealtime},
    {"processWatch", cfg_.processWatch},
    {"networkWatch", cfg_.networkWatch},
    {"networkPollMs", cfg_.networkPollMs},
    {"processPollMs", cfg_.processPollMs},
    {"scheduleHour", cfg_.scheduleHour},
    {"scheduleMinute", cfg_.scheduleMinute},
    {"scheduleType", cfg_.scheduleType},
    {"clamavEnabled", cfg_.clamavEnabled},
    {"clamavDbDir", cfg_.clamavDbDir},
    {"clamavMaxFileMb", cfg_.clamavMaxFileMb},
    {"onAccessBlocking", cfg_.onAccessBlocking},
    {"onAccessScanOpen", cfg_.onAccessScanOpen},
    {"onAccessPaths", cfg_.onAccessPaths},
    {"onAccessTimeoutMs", cfg_.onAccessTimeoutMs},
    {"onAccessMaxFileMb", cfg_.onAccessMaxFileMb},
    {"killMalicious", cfg_.killMalicious},
    {"networkBlocking", cfg_.networkBlocking},
    {"rulesAutoUpdate", cfg_.rulesAutoUpdate},
    {"rulesUrl", cfg_.rulesUrl},
    {"rulesUpdateHours", cfg_.rulesUpdateHours},
    {"rulesPublicKey", cfg_.rulesPublicKey},
    {"fileScanMaxFileMb", cfg_.fileScanMaxFileMb},
    {"ransomShield", cfg_.ransomShield},
    {"execProtection", cfg_.execProtection},
    {"persistenceGuard", cfg_.persistenceGuard},
    {"revShellWatch", cfg_.revShellWatch},
    {"privEscWatch", cfg_.privEscWatch},
    {"execAllowList", cfg_.execAllowList},
    {"adminGroups", cfg_.adminGroups}
  };
  std::string tmp = p + ".tmp";
  {
    std::ofstream out(tmp);
    if (!out) return false;
    out << j.dump(2) << "\n";
    if (!out) return false;
  }
  std::error_code ec;
  fs::rename(tmp, p, ec);
  return !ec;
}

} // namespace oreon
