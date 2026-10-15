#include "TrayState.hpp"
#include <QCoreApplication>
#include <QJsonObject>
#include <iostream>

static int failures = 0;
static void check(bool c, const char* m) { if (!c) { std::cerr << "FAIL: " << m << "\n"; ++failures; } }

static QJsonObject clam(bool enabled, bool avail, bool loading) {
  return QJsonObject{{"enabled", enabled}, {"available", avail}, {"loading", loading}};
}
static QJsonObject st(int threats, bool f, bool p, bool n, QJsonObject c) {
  return QJsonObject{{"threatCount", threats}, {"fileRealtime", f}, {"processWatch", p},
                     {"networkWatch", n}, {"clamav", c}};
}

int main(int argc, char** argv) {
  QCoreApplication app(argc, argv);
  using S = TrayState::State;

  check(TrayState::evaluate({}, false, false, -1).state == S::Offline, "offline when disconnected");

  auto good = st(0, true, true, true, clam(true, true, false));
  check(TrayState::evaluate(good, true, false, -1).state == S::Protected, "protected");

  check(TrayState::evaluate(st(2, true, true, true, clam(true, true, false)), true, false, -1).state == S::AtRisk, "atrisk");

  check(TrayState::evaluate(good, true, true, 42).state == S::Scanning, "scanning");

  check(TrayState::evaluate(st(0, false, false, false, clam(true, true, false)), true, false, -1).state == S::Off, "off");
  check(TrayState::evaluate(st(0, true, false, true, clam(true, true, false)), true, false, -1).state == S::PartlyOff, "partly off");
  check(TrayState::evaluate(st(0, true, true, true, clam(true, false, false)), true, false, -1).state == S::OutOfDate, "out of date");

  check(TrayState::evaluate(good, true, false, -1).baseIcon == "security-high", "protected icon");
  check(TrayState::evaluate(st(1, true, true, true, clam(true, true, false)), true, false, -1).baseIcon == "security-low", "atrisk icon");

  check(TrayState::evaluate(st(1, true, true, true, clam(true, true, false)), true, true, 50).state == S::AtRisk, "atrisk while scanning");
  check(TrayState::evaluate(st(1, true, false, true, clam(true, false, false)), true, false, -1).state == S::AtRisk, "atrisk over partly off");
  check(TrayState::evaluate(st(1, false, false, false, clam(true, true, false)), true, false, -1).state == S::AtRisk, "atrisk over off");
  QJsonObject big = good; big["threatCount"] = 3.0;
  check(TrayState::evaluate(big, true, false, -1).state == S::AtRisk, "double threatCount");
  check(TrayState::activeThreats(big) == 3, "activeThreats");
  check(TrayState::evaluate(st(0, true, true, true, clam(true, true, false)), true, false, -1).baseIcon == "security-high", "resolved icon");

  if (failures) return 1;
  std::cout << "ok\n";
  return 0;
}
