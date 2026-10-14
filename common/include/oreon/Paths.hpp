#pragma once
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <filesystem>

namespace oreon {
namespace fs = std::filesystem;

inline bool isRoot() { return geteuid() == 0; }

inline std::string homeDir() {
  const char* h = getenv("HOME");
  return h ? h : "/tmp";
}

inline void ensureDir(const std::string& p) {
  std::error_code ec;
  fs::create_directories(p, ec);
}

inline std::string defaultDataDir() {
  if (isRoot()) return "/var/lib/oreon-defense";
  return homeDir() + "/.local/share/oreon-defense";
}

inline std::string defaultConfigDir() {
  if (isRoot()) return "/etc/oreon-defense";
  return homeDir() + "/.config/oreon-defense";
}

inline std::string defaultSocketPath() {
  if (isRoot()) return "/run/oreon-defense/daemon.sock";
  return defaultDataDir() + "/daemon.sock";
}

inline std::string defaultQuarantineDir() {
  return defaultDataDir() + "/quarantine";
}

inline std::string defaultRulesPath() {
  if (fs::exists("/usr/share/oreon-defense/rules/starter-rules.yaml"))
    return "/usr/share/oreon-defense/rules/starter-rules.yaml";
  if (fs::exists("/etc/oreon-defense/rules/starter-rules.yaml"))
    return "/etc/oreon-defense/rules/starter-rules.yaml";
  return defaultDataDir() + "/rules/starter-rules.yaml";
}

inline std::string defaultLogPath() {
  return defaultDataDir() + "/events.jsonl";
}

} // namespace oreon
