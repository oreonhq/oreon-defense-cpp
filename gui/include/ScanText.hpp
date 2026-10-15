#pragma once
#include <QCoreApplication>
#include <QLocale>
#include <QString>
#include <algorithm>

namespace ScanText {

inline int detectionCount(qint64 daemonCount, int listed) {
  const qint64 n = std::max<qint64>(daemonCount < 0 ? 0 : daemonCount, listed < 0 ? 0 : listed);
  return n > 1000000 ? 1000000 : int(n);
}

inline QString threats(int n) {
  if (n <= 0) return QCoreApplication::translate("ScansPage", "no threats found");
  if (n == 1) return QCoreApplication::translate("ScansPage", "1 threat found");
  return QCoreApplication::translate("ScansPage", "%1 threats found").arg(QLocale().toString(n));
}

inline QString finished(bool cancelled, int n) {
  return (cancelled ? QCoreApplication::translate("ScansPage", "Scan cancelled")
                    : QCoreApplication::translate("ScansPage", "Scan finished"))
         + QStringLiteral(", ") + threats(n);
}

}
