#include <oreon/ThreatState.hpp>
#include <iostream>

using namespace oreon;
static int failures = 0;
static void check(bool c, const char* m) { if (!c) { std::cerr << "FAIL: " << m << "\n"; ++failures; } }

static Threat mk(ThreatAction a, Severity s = Severity::High, bool heur = false) {
  Threat t; t.action = a; t.severity = s; t.heuristic = heur; t.name = "Unix.Trojan.Mirai-7100807-0";
  return t;
}

int main() {
  check(isActiveThreat(mk(ThreatAction::Detected)), "detected is active");
  check(isActiveThreat(mk(ThreatAction::Blocked)), "blocked file still present");
  check(!isActiveThreat(mk(ThreatAction::Quarantined)), "quarantined resolves");
  check(!isActiveThreat(mk(ThreatAction::Deleted)), "deleted resolves");
  check(!isActiveThreat(mk(ThreatAction::Allowed)), "allowed resolves");
  check(!isActiveThreat(mk(ThreatAction::Restored)), "restored resolves");
  check(!isActiveThreat(mk(ThreatAction::Detected, Severity::Low)), "low ignored");
  check(!isActiveThreat(mk(ThreatAction::Detected, Severity::Medium, true)), "heuristic ignored");
  std::vector<Threat> v{mk(ThreatAction::Detected), mk(ThreatAction::Quarantined), mk(ThreatAction::Detected)};
  check(countActiveThreats(v) == 2, "count");
  v[0].action = ThreatAction::Quarantined; v[2].action = ThreatAction::Allowed;
  check(countActiveThreats(v) == 0, "all resolved");
  if (failures) return 1;
  std::cout << "ok\n";
  return 0;
}
