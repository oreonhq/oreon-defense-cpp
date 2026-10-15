#include "NotifyText.hpp"
#include <QCoreApplication>
#include <iostream>

static int failures = 0;
static void check(bool c, const char* m) { if (!c) { std::cerr << "FAIL: " << m << "\n"; ++failures; } }

int main(int argc, char** argv) {
  QCoreApplication app(argc, argv);

  check(NotifyText::fileName("/home/me/Downloads/eicar.com") == "eicar.com", "filename");
  check(NotifyText::folderOf("/home/me/Downloads/eicar.com") == "Downloads", "folder");

  QJsonObject q{{"path", "/home/me/Downloads/eicar.com"}, {"name", "Eicar-Test-Signature"}, {"action", 1}};
  auto t = NotifyText::quarantined(q);
  check(t.title == "Oreon Defense blocked a dangerous file", "quarantine title");
  check(t.body.contains("eicar.com") && t.body.contains("Downloads"), "quarantine body file+folder");
  check(t.body.contains("can't harm"), "quarantine reassurance");
  check(!t.body.contains("/home/me"), "no full path in body");

  QJsonObject qo = q;
  qo["originUrl"] = "https://example.test/x";
  check(NotifyText::quarantined(qo).body.contains("example.test"), "origin shown");

  check(NotifyText::humanThreat("Eicar-Test").contains("test file"), "human eicar");
  check(NotifyText::humanThreat("Trojan.Linux.Agent").contains("trojan"), "human trojan");

  auto s = NotifyText::summary(3, 3, 0, 0);
  check(s.title.contains("3"), "summary count");

  for (const QString& txt : {t.title, t.body, s.title, s.body}) {
    check(!txt.contains(QChar(0x2014)), "no em dash");
    check(!txt.contains('!'), "no exclamation");
  }

  if (failures) return 1;
  std::cout << "ok\n";
  return 0;
}
