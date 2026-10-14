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
  cfg_.watchPaths = {
    home + "/Downloads",
    home + "/Desktop",
    home + "/Documents",
    "/tmp"
  };
  cfg_.exclusions = {
    home + "/.cache",
    home + "/.local/share/oreon-defense",
    "/var/lib/oreon-defense",
    "/proc",
    "/sys",
    "/dev",
    "/run"
  };
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
  try {
    json j;
    in >> j;
    if (j.contains("watchPaths")) cfg_.watchPaths = j["watchPaths"].get<std::vector<std::string>>();
    if (j.contains("exclusions")) cfg_.exclusions = j["exclusions"].get<std::vector<std::string>>();
    cfg_.quarantineDir = j.value("quarantineDir", cfg_.quarantineDir);
    cfg_.dataDir = j.value("dataDir", cfg_.dataDir);
    cfg_.rulesPath = j.value("rulesPath", cfg_.rulesPath);
    cfg_.socketPath = j.value("socketPath", cfg_.socketPath);
    cfg_.logPath = j.value("logPath", cfg_.logPath);
    cfg_.fileRealtime = j.value("fileRealtime", true);
    cfg_.processWatch = j.value("processWatch", true);
    cfg_.networkWatch = j.value("networkWatch", true);
    cfg_.networkPollMs = j.value("networkPollMs", 2000);
    cfg_.processPollMs = j.value("processPollMs", 1500);
    cfg_.scheduleHour = j.value("scheduleHour", -1);
    cfg_.scheduleMinute = j.value("scheduleMinute", 0);
    cfg_.scheduleType = j.value("scheduleType", "none");
  } catch (const std::exception& e) {
    std::cerr << "config load error: " << e.what() << "\n";
    return false;
  }
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
    {"scheduleType", cfg_.scheduleType}
  };
  std::ofstream out(p);
  if (!out) return false;
  out << j.dump(2) << "\n";
  return true;
}

} // namespace oreon
