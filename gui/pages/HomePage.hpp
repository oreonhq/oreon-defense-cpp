#pragma once
#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QFormLayout>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QStyle>
#include <QDateTime>
#include <QLocale>
#include <QJsonObject>
#include <QTimer>
#include "DaemonClient.hpp"
#include "Theme.hpp"
#include "TrayState.hpp"

class HomePage : public QWidget {
  Q_OBJECT
public:
  HomePage(DaemonClient* client, QWidget* parent = nullptr)
    : QWidget(parent), client_(client) {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(Theme::spacing(this));

    auto* statusRow = new QHBoxLayout;
    statusRow->setSpacing(Theme::spacing(this) * 2);
    statusIcon_ = new QLabel;
    iconSize_ = style()->pixelMetric(QStyle::PM_LargeIconSize, nullptr, this) * 3 / 2;
    statusIcon_->setFixedSize(iconSize_, iconSize_);
    auto* statusText = new QVBoxLayout;
    statusText->setSpacing(0);
    statusTitle_ = new QLabel;
    statusTitle_->setFont(Theme::scaledFont(statusTitle_->font(), 1.5));
    statusTitle_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    statusHint_ = new QLabel(tr("Start oreon-defense.service to turn on protection."));
    statusHint_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    Theme::makeSecondary(statusHint_);
    statusText->addStretch(1);
    statusText->addWidget(statusTitle_);
    statusText->addWidget(statusHint_);
    statusText->addStretch(1);
    statusRow->addWidget(statusIcon_, 0, Qt::AlignVCenter);
    statusRow->addLayout(statusText, 1);
    root->addLayout(statusRow);
    Theme::addSectionGap(root, this);

    auto* content = new QVBoxLayout;
    content->setSpacing(Theme::spacing(this));
    content->setContentsMargins(iconSize_ + statusRow->spacing(), 0, 0, 0);
    root->addLayout(content);

    form_ = Theme::form(this);
    auto value = [] {
      auto* l = new QLabel;
      l->setTextInteractionFlags(Qt::TextSelectableByMouse);
      return l;
    };
    realtimeVal_ = value();
    threatsVal_ = value();
    sigVal_ = value();
    rulesVal_ = value();
    lastScanVal_ = value();
    form_->addRow(tr("Real-time protection:"), realtimeVal_);
    form_->addRow(tr("Active threats:"), threatsVal_);
    form_->addRow(tr("Virus signatures:"), sigVal_);
    form_->addRow(tr("Detection rules:"), rulesVal_);
    form_->addRow(tr("Last scan:"), lastScanVal_);
    content->addLayout(form_);
    Theme::addSectionGap(content, this);

    auto* buttons = new QHBoxLayout;
    buttons->setSpacing(Theme::spacing(this));
    quick_ = new QPushButton(Theme::icon({"system-search", "edit-find"}), tr("Quick Scan"));
    quick_->setToolTip(tr("Scan common places like Downloads and Desktop"));
    update_ = new QPushButton(Theme::icon({"update-none", "download", "view-refresh"}), tr("Update Rules"));
    update_->setToolTip(tr("Download the latest signed detection rules"));
    buttons->addWidget(quick_);
    buttons->addWidget(update_);
    buttons->addStretch(1);
    content->addLayout(buttons);
    root->addStretch(1);

    connect(quick_, &QPushButton::clicked, this, [this] { client_->startScan("quick"); });
    connect(update_, &QPushButton::clicked, this, [this] { client_->updateRulesNow(); });

    setOffline();

    auto* refresh = new QTimer(this);
    connect(refresh, &QTimer::timeout, this, [this] {
      if (connected_ && isVisible()) client_->getStatus();
    });
    refresh->start(10000);

    connect(client_, &DaemonClient::statusUpdated, this, &HomePage::onStatus);
    connect(client_, &DaemonClient::connectedChanged, this, [this](bool ok) {
      connected_ = ok;
      if (!ok) setOffline();
    });
    connect(client_, &DaemonClient::threatEvent, this, [this](const QJsonObject&) {
      client_->getStatus();
    });
    connect(client_, &DaemonClient::rulesUpdated, this, [this](const QJsonObject& r) {
      showRules(r);
    });
  }

private:
  void setStatus(const QStringList& icons, const QString& title) {
    statusIcon_->setPixmap(Theme::icon(icons).pixmap(iconSize_, iconSize_));
    statusTitle_->setText(title);
  }

  void setFactsVisible(bool on) {
    for (int i = 0; i < form_->rowCount(); ++i) form_->setRowVisible(i, on);
    quick_->setEnabled(on);
    update_->setEnabled(on);
  }

  void setOffline() {
    setStatus({"security-low", "dialog-error"}, tr("Service not running"));
    statusHint_->show();
    setFactsVisible(false);
  }

  void onStatus(const QJsonObject& s) {
    connected_ = true;
    statusHint_->hide();
    setFactsVisible(true);

    const bool fileRt = s.value("fileRealtime").toBool(true);
    const bool proc = s.value("processWatch").toBool(true);
    const bool net = s.value("networkWatch").toBool(true);
    const qulonglong threats = s.value("threatCount").toVariant().toULongLong();
    const auto p = TrayState::evaluate(s, true, false, -1);
    switch (p.state) {
    case TrayState::State::AtRisk:
      setStatus({"security-low", "dialog-warning"}, tr("At risk"));
      break;
    case TrayState::State::Off:
      setStatus({"security-medium", "dialog-warning"}, tr("Protection is off"));
      break;
    case TrayState::State::PartlyOff:
      setStatus({"security-medium", "dialog-warning"}, tr("Protection is partly off"));
      break;
    case TrayState::State::OutOfDate:
      setStatus({"security-medium", "dialog-warning"}, tr("Virus signatures need attention"));
      break;
    default:
      setStatus({"security-high", "emblem-ok"}, tr("Protected"));
      break;
    }

    form_->setRowVisible(threatsVal_, threats > 0);
    threatsVal_->setText(QString::number(threats));

    QString rt = fileRt ? tr("On") : tr("Off");
    QStringList tip;
    if (s.contains("onAccess")) {
      const QJsonObject o = s.value("onAccess").toObject();
      const QString mode = o.value("mode").toString();
      if (!o.value("enabled").toBool(true) || mode == QLatin1String("off"))
        tip << tr("Blocking before files open: off");
      else if (mode == QLatin1String("fanotify"))
        tip << tr("Blocking before files open: on, %1 blocked so far")
                 .arg(QLocale().toString(o.value("denied").toVariant().toULongLong()));
      else {
        if (fileRt) rt = tr("Limited");
        tip << tr("Blocking before files open: not available, new files are checked after they are written");
      }
    }
    tip << (proc ? tr("Process monitoring: on") : tr("Process monitoring: off"));
    tip << (net ? tr("Network monitoring: on") : tr("Network monitoring: off"));
    if (s.contains("networkBlocking")) {
      const QJsonObject n = s.value("networkBlocking").toObject();
      if (!n.value("enabled").toBool(true)) tip << tr("Network blocking: off");
      else if (n.value("active").toBool())
        tip << tr("Network blocking: on, %1 blocked addresses")
                 .arg(QLocale().toString(n.value("count").toInt()));
      else tip << tr("Network blocking: not active");
    }
    realtimeVal_->setText(rt);
    realtimeVal_->setToolTip(tip.join(QLatin1Char('\n')));

    if (s.contains("clamav")) {
      const QJsonObject c = s.value("clamav").toObject();
      if (!c.value("enabled").toBool(true)) {
        sigVal_->setText(tr("Off"));
        sigVal_->setToolTip(QString());
      } else if (c.value("available").toBool()) {
        const qint64 db = c.value("dbTime").toVariant().toLongLong();
        const QString date = db > 0
          ? QLocale().toString(QDateTime::fromSecsSinceEpoch(db).date(), QLocale::ShortFormat)
          : tr("unknown date");
        sigVal_->setText(tr("ClamAV database %1, %2")
          .arg(c.value("dailyVersion").toInt()).arg(date));
        sigVal_->setToolTip(tr("ClamAV %1, %2 signatures")
          .arg(c.value("libVersion").toString(),
               QLocale().toString(c.value("signatures").toVariant().toULongLong())));
      } else if (c.value("loading").toBool()) {
        sigVal_->setText(tr("Loading"));
      } else {
        sigVal_->setText(tr("Not available"));
        sigVal_->setToolTip(c.value("error").toString());
      }
    } else {
      sigVal_->setText(tr("Unknown"));
    }

    if (s.contains("rules")) showRules(s.value("rules").toObject());
    else rulesVal_->setText(tr("Unknown"));

    lastScanVal_->setText(Theme::when(s.value("lastScan").toVariant().toLongLong()));
  }

  void showRules(const QJsonObject& r) {
    QString t = tr("Version %1").arg(r.value("version").toVariant().toLongLong());
    const QString err = r.value("lastError").toString();
    if (r.value("running").toBool()) t += tr(", checking for updates");
    else if (!err.isEmpty()) t += tr(", last update failed");
    rulesVal_->setText(t);
    QString tip = tr("%1 rules, last checked %2")
      .arg(QLocale().toString(r.value("count").toInt()),
           Theme::when(r.value("lastCheck").toVariant().toLongLong()));
    if (!err.isEmpty()) tip += QLatin1Char('\n') + err;
    rulesVal_->setToolTip(tip);
  }

  DaemonClient* client_;
  bool connected_{false};
  int iconSize_{48};
  QLabel* statusIcon_;
  QLabel* statusTitle_;
  QLabel* statusHint_;
  QFormLayout* form_;
  QLabel* realtimeVal_;
  QLabel* threatsVal_;
  QLabel* sigVal_;
  QLabel* rulesVal_;
  QLabel* lastScanVal_;
  QPushButton* quick_;
  QPushButton* update_;
};
