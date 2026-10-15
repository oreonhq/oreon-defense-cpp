#include "ScanText.hpp"
#include <QCoreApplication>
#include <iostream>

static int failures = 0;
static void check(bool c, const char* m) { if (!c) { std::cerr << "FAIL: " << m << "\n"; ++failures; } }

int main(int argc, char** argv) {
  QCoreApplication app(argc, argv);
  check(ScanText::detectionCount(0, 1) == 1, "listed hit counts");
  check(ScanText::finished(false, ScanText::detectionCount(0, 1)) == "Scan finished, 1 threat found", "one threat text");
  check(ScanText::detectionCount(3, 1) == 3, "daemon count wins when higher");
  check(ScanText::detectionCount(0, 0) == 0, "clean");
  check(ScanText::detectionCount(-5, 0) == 0, "negative clamps");
  check(ScanText::finished(false, 0) == "Scan finished, no threats found", "clean text");
  check(ScanText::finished(true, 2).startsWith("Scan cancelled, 2"), "cancelled text");
  if (failures) return 1;
  std::cout << "ok\n";
  return 0;
}
