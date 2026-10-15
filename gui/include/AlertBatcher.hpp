#pragma once
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

class AlertBatcher {
public:
  struct Alert {
    bool summary{false};
    bool strong{false};
    QJsonObject threat;
    int count{0};
    int quarantined{0};
    int blocked{0};
    int killed{0};
    QStringList paths;
  };

  static constexpr int kWindowMs = 1500;
  static constexpr qint64 kDedupeMs = 10 * 60 * 1000;
  static constexpr qint64 kWeakGapMs = 5 * 60 * 1000;

  static bool isStrong(const QJsonObject& threat);

  bool add(const QJsonObject& threat, qint64 nowMs);

  QList<Alert> flush(qint64 nowMs);

  int held() const { return weakHeld_; }

private:
  static Alert build(const QList<QJsonObject>& items, bool strong, int extra);

  QList<QJsonObject> strong_;
  QList<QJsonObject> weak_;
  QHash<QString, qint64> seen_;
  qint64 lastWeakShown_{-1};
  int weakHeld_{0};
  bool armed_{false};
};
