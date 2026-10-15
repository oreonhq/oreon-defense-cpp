#pragma once
#include <oreon/Types.hpp>
#include <cstdint>
#include <vector>

namespace oreon {

inline bool isActiveThreat(const Threat& t) {
  if (t.heuristic || t.severity < Severity::Medium) return false;
  return t.action == ThreatAction::Detected || t.action == ThreatAction::Blocked ||
         t.action == ThreatAction::Killed;
}

inline uint64_t countActiveThreats(const std::vector<Threat>& threats) {
  uint64_t n = 0;
  for (const auto& t : threats) if (isActiveThreat(t)) ++n;
  return n;
}

}
