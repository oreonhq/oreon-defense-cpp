#include "AlertBatcher.hpp"
#include <QJsonObject>
#include <iostream>

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::cerr << "FAIL: " << msg << "\n"; ++failures; } \
                              else std::cout << "ok: " << msg << "\n"; } while (0)

static QJsonObject threat(const QString& path, const QString& sev, int action, bool heuristic,
                          const QString& rule = QStringLiteral("r"), const QString& engine = QStringLiteral("rules")) {
  QJsonObject t;
  t["path"] = path;
  t["severity"] = sev;
  t["action"] = action;
  t["heuristic"] = heuristic;
  t["ruleId"] = rule;
  t["engine"] = engine;
  t["kind"] = QStringLiteral("file");
  t["name"] = QStringLiteral("n");
  return t;
}

int main() {
  CHECK(AlertBatcher::isStrong(threat("/a", "high", 0, false, "clamav", "clamav")), "ClamAV hit is strong");
  CHECK(AlertBatcher::isStrong(threat("/a", "high", 1, false)), "quarantined is strong");
  CHECK(!AlertBatcher::isStrong(threat("/a", "low", 0, true)), "heuristic is not strong");
  CHECK(!AlertBatcher::isStrong(threat("/a", "medium", 0, true)), "medium heuristic (old feed) is not strong");
  CHECK(!AlertBatcher::isStrong(threat("/a", "medium", 0, false)), "medium rule is not strong");

  {
    AlertBatcher b;
    qint64 t = 1000;
    bool armed = false;
    int arms = 0;
    for (int i = 0; i < 50; ++i) {
      armed = b.add(threat(QStringLiteral("/var/tmp/dracut.x/usr/bin/f%1").arg(i), "low", 0, true), t + i);
      if (armed) ++arms;
    }
    CHECK(arms == 1, "timer armed once per burst");
    auto out = b.flush(t + AlertBatcher::kWindowMs);
    CHECK(out.size() == 1, "burst of 50 heuristic hits gives one notification");
    CHECK(out.size() == 1 && out[0].summary && !out[0].strong && out[0].count == 50,
          "it is a suspicious summary with the count");

    t += 60 * 1000;
    b.add(threat("/tmp/other", "low", 0, true), t);
    out = b.flush(t + AlertBatcher::kWindowMs);
    CHECK(out.isEmpty(), "second suspicious burst within the gap shows nothing");
    CHECK(b.held() == 1, "held item counted");

    b.add(threat("/home/u/Downloads/eicar.com", "high", 1, false, "clamav", "clamav"), t + 10);
    out = b.flush(t + 10 + AlertBatcher::kWindowMs);
    CHECK(out.size() == 1 && out[0].strong && !out[0].summary, "single real threat shows on its own");

    t += AlertBatcher::kWeakGapMs + 1;
    b.add(threat("/tmp/third", "low", 0, true), t);
    out = b.flush(t + AlertBatcher::kWindowMs);
    CHECK(out.size() == 1 && out[0].summary && out[0].count == 2, "held items folded into the next note");
  }
  {
    AlertBatcher b;
    b.add(threat("/tmp/x", "low", 0, true), 0);
    b.add(threat("/tmp/x", "low", 0, true), 10);
    auto out = b.flush(AlertBatcher::kWindowMs);
    CHECK(out.size() == 1 && !out[0].summary, "duplicate event deduplicated");
    CHECK(!b.add(threat("/tmp/x", "low", 0, true), AlertBatcher::kWeakGapMs + 10),
          "same file and rule stays quiet within the dedupe window");
  }
  {
    AlertBatcher b;
    for (int i = 0; i < 5; ++i)
      b.add(threat(QStringLiteral("/home/u/s/%1").arg(i), "high", 1, false, "eicar-test"), i);
    b.add(threat("/home/u/s/odd", "low", 0, true, "tmp-elf-heuristic"), 6);
    auto out = b.flush(AlertBatcher::kWindowMs);
    CHECK(out.size() == 2, "strong and weak items give one note each");
    CHECK(!out.isEmpty() && out[0].strong && out[0].summary && out[0].count == 5 && out[0].quarantined == 5,
          "strong summary counts quarantined files");
  }
  if (failures) {
    std::cerr << failures << " check(s) failed\n";
    return 1;
  }
  std::cout << "alerts ok\n";
  return 0;
}
