#pragma once
#include <QString>
#include <QJsonObject>
#include <QFileInfo>

namespace NotifyText {

inline QString folderOf(const QString& path) {
  const QString dir = QFileInfo(path).absolutePath();
  return QFileInfo(dir).fileName();
}

inline QString fileName(const QString& path) {
  return QFileInfo(path).fileName();
}

inline QString humanThreat(const QString& rawName) {
  const QString n = rawName.toLower();
  if (n.contains("eicar")) return QObject::tr("a harmless antivirus test file");
  if (n.contains("ransom") || n.contains("locky") || n.contains("wcry") || n.contains("crypt"))
    return QObject::tr("a file that locks your files for ransom");
  if (n.contains("trojan")) return QObject::tr("a trojan");
  if (n.contains("miner") || n.contains("coinminer") || n.contains("xmr"))
    return QObject::tr("a program that mines cryptocurrency");
  if (n.contains("worm")) return QObject::tr("a worm");
  if (n.contains("backdoor") || n.contains("rat")) return QObject::tr("a backdoor");
  if (n.contains("dropper")) return QObject::tr("a program that installs other harmful software");
  if (n.contains("pua") || n.contains("adware")) return QObject::tr("an unwanted program");
  return QObject::tr("a dangerous file");
}

struct Text {
  QString title;
  QString body;
};

inline Text quarantined(const QJsonObject& t) {
  Text x;
  const QString name = NotifyText::fileName(t.value("path").toString());
  const QString folder = NotifyText::folderOf(t.value("path").toString());
  x.title = QObject::tr("Oreon Defense blocked a dangerous file");
  if (!folder.isEmpty())
    x.body = QObject::tr("%1 in %2 was moved to quarantine. It can't harm your computer.")
               .arg(name, folder);
  else
    x.body = QObject::tr("%1 was moved to quarantine. It can't harm your computer.").arg(name);
  const QString origin = t.value("originUrl").toString();
  if (!origin.isEmpty()) x.body += QObject::tr("\nDownloaded from %1").arg(origin);
  return x;
}

inline Text blocked(const QJsonObject& t) {
  Text x;
  const QString name = NotifyText::fileName(t.value("path").toString());
  x.title = QObject::tr("Oreon Defense blocked a dangerous file");
  x.body = QObject::tr("%1 was stopped before it could open. It can't harm your computer.").arg(name);
  return x;
}

inline Text suspicious(const QJsonObject& t) {
  Text x;
  const QString name = NotifyText::fileName(t.value("path").toString());
  x.title = QObject::tr("A file looks unusual");
  x.body = QObject::tr("%1 looks unusual. Nothing was blocked or moved.").arg(name);
  return x;
}

inline Text processKilled(const QJsonObject& t) {
  Text x;
  x.title = QObject::tr("Oreon Defense stopped a harmful program");
  const QString name = t.value("name").toString();
  x.body = name.isEmpty() ? QObject::tr("A harmful program was stopped.")
                          : QObject::tr("%1 was stopped.").arg(name);
  return x;
}

inline Text network() {
  Text x;
  x.title = QObject::tr("Oreon Defense blocked a connection");
  x.body = QObject::tr("Blocked a connection to a known bad address.");
  return x;
}

inline Text summary(int count, int quarantined, int blocked, int killed) {
  Text x;
  x.title = QObject::tr("Oreon Defense blocked %n dangerous file(s)", "", count);
  QStringList parts;
  if (quarantined) parts << QObject::tr("%n moved to quarantine", "", quarantined);
  if (blocked) parts << QObject::tr("%n stopped before opening", "", blocked);
  if (killed) parts << QObject::tr("%n program(s) stopped", "", killed);
  x.body = parts.isEmpty() ? QObject::tr("They can't harm your computer.")
                           : parts.join(QObject::tr(", ")) + QStringLiteral(".");
  return x;
}

}
