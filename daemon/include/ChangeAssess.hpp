#pragma once
#include "SystemTrust.hpp"
#include <oreon/Types.hpp>
#include <string>
#include <vector>

namespace oreon {
namespace change {

enum class FileKind {
  Passwd, Shadow, Group, GShadow, Sudoers, AuthorizedKeys, Preload, Canary, Persistence
};
FileKind kindOf(const std::string& path);

struct Delta {
  std::vector<std::string> critical;
  bool criticalIsTop{false};
  std::vector<std::string> notes;
  std::vector<std::string> grants;
  bool malformed{false};
  std::string malformedWhy;
};
Delta analyze(const std::string& path, const std::string& before, const std::string& after);

struct Event {
  std::string path;
  std::string before;
  std::string after;
  bool attributed{false};
  trust::ActorVerdict actor;
  bool packageCopy{false};
};

struct Verdict {
  bool alert{false};
  Severity severity{Severity::Info};
  std::string category;
  std::string title;
  std::string message;
  std::string detail;
  std::vector<std::string> reasons;
  bool killWriter{false};
};

Verdict assess(const Event& e);

bool matchesRpm(const std::string& path);

}
}
