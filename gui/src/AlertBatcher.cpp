#include "AlertBatcher.hpp"

bool AlertBatcher::isStrong(const QJsonObject& t) {
  if (t.value(QStringLiteral("heuristic")).toBool(false)) return false;
  const int action = t.value(QStringLiteral("action")).toInt(0);
  if (action == 1 || action == 5 || action == 6) return true;
  const QString sev = t.value(QStringLiteral("severity")).toString();
  return sev == QLatin1String("high") || sev == QLatin1String("critical");
}

bool AlertBatcher::add(const QJsonObject& t, qint64 nowMs) {
  const bool strong = isStrong(t);
  const QString key = t.value(QStringLiteral("kind")).toString() + QLatin1Char('|') +
                      t.value(QStringLiteral("path")).toString() + QLatin1Char('|') +
                      t.value(QStringLiteral("ruleId")).toString() + QLatin1Char('|') +
                      (strong ? QString::number(t.value(QStringLiteral("action")).toInt(0))
                              : QStringLiteral("weak"));
  auto it = seen_.find(key);
  if (it != seen_.end() && nowMs - it.value() < kDedupeMs) return false;
  if (seen_.size() > 4096) {
    for (auto s = seen_.begin(); s != seen_.end();) {
      if (nowMs - s.value() >= kDedupeMs) s = seen_.erase(s);
      else ++s;
    }
  }
  seen_.insert(key, nowMs);
  (strong ? strong_ : weak_).append(t);
  if (armed_) return false;
  armed_ = true;
  return true;
}

AlertBatcher::Alert AlertBatcher::build(const QList<QJsonObject>& items, bool strong, int extra) {
  Alert a;
  a.strong = strong;
  a.count = items.size() + extra;
  a.summary = a.count > 1;
  if (!a.summary) a.threat = items.first();
  for (const auto& t : items) {
    switch (t.value(QStringLiteral("action")).toInt(0)) {
      case 1: ++a.quarantined; break;
      case 5: ++a.blocked; break;
      case 6: ++a.killed; break;
      default: break;
    }
    if (a.paths.size() < 3) a.paths << t.value(QStringLiteral("path")).toString();
  }
  return a;
}

QList<AlertBatcher::Alert> AlertBatcher::flush(qint64 nowMs) {
  armed_ = false;
  QList<Alert> out;
  if (!strong_.isEmpty()) out << build(strong_, true, 0);
  if (!weak_.isEmpty()) {
    if (lastWeakShown_ >= 0 && nowMs - lastWeakShown_ < kWeakGapMs) {
      weakHeld_ += weak_.size();
    } else {
      out << build(weak_, false, weakHeld_);
      weakHeld_ = 0;
      lastWeakShown_ = nowMs;
    }
  }
  strong_.clear();
  weak_.clear();
  return out;
}
