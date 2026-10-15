#pragma once
#include <QString>
#include <QJsonObject>

namespace TrayState {

enum class State {
  Offline,
  AtRisk,
  Scanning,
  Off,
  PartlyOff,
  OutOfDate,
  Protected
};

struct Presentation {
  State state{State::Protected};
  QString baseIcon;
  QString emblem;
  bool disabled{false};
  QString tooltip;
};

inline int activeThreats(const QJsonObject& status) {
  return status.value(QStringLiteral("threatCount")).toVariant().toInt();
}

inline Presentation evaluate(const QJsonObject& status, bool connected,
                             bool scanning, int scanPercent) {
  Presentation p;
  if (!connected) {
    p.state = State::Offline;
    p.baseIcon = QStringLiteral("security-high");
    p.disabled = true;
    p.tooltip = QObject::tr("Oreon Defense is not running");
    return p;
  }

  const int threats = activeThreats(status);
  const bool file = status.value(QStringLiteral("fileRealtime")).toBool(true);
  const bool proc = status.value(QStringLiteral("processWatch")).toBool(true);
  const bool net = status.value(QStringLiteral("networkWatch")).toBool(true);
  const int onCount = (file ? 1 : 0) + (proc ? 1 : 0) + (net ? 1 : 0);

  const QJsonObject clam = status.value(QStringLiteral("clamav")).toObject();
  const bool clamEnabled = clam.value(QStringLiteral("enabled")).toBool(false);
  const bool clamReady = clam.value(QStringLiteral("available")).toBool(false);
  const bool clamLoading = clam.value(QStringLiteral("loading")).toBool(false);
  const bool sigsStale = clamEnabled && !clamReady && !clamLoading;

  if (threats > 0) {
    p.state = State::AtRisk;
    p.baseIcon = QStringLiteral("security-low");
    p.emblem = QStringLiteral("emblem-important");
    p.tooltip = QObject::tr("At risk: %n active threat(s)", "", threats);
    return p;
  }
  if (scanning) {
    p.state = State::Scanning;
    p.baseIcon = QStringLiteral("security-medium");
    p.emblem = QStringLiteral("view-refresh");
    p.tooltip = scanPercent >= 0 && scanPercent <= 100
      ? QObject::tr("Scanning %1%").arg(scanPercent)
      : QObject::tr("Scanning");
    return p;
  }
  if (onCount == 0) {
    p.state = State::Off;
    p.baseIcon = QStringLiteral("security-medium");
    p.emblem = QStringLiteral("emblem-important");
    p.tooltip = QObject::tr("Protection is off");
    return p;
  }
  if (onCount < 3) {
    p.state = State::PartlyOff;
    p.baseIcon = QStringLiteral("security-medium");
    p.tooltip = QObject::tr("Protection is partly off");
    return p;
  }
  if (sigsStale) {
    p.state = State::OutOfDate;
    p.baseIcon = QStringLiteral("security-medium");
    p.emblem = QStringLiteral("dialog-warning");
    p.tooltip = QObject::tr("Virus signatures need attention");
    return p;
  }
  p.state = State::Protected;
  p.baseIcon = QStringLiteral("security-high");
  p.tooltip = QObject::tr("Protected");
  return p;
}

}
