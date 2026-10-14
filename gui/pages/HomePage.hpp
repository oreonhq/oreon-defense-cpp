#pragma once
#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QGroupBox>
#include <QFormLayout>
#include <QTreeWidget>
#include <QHeaderView>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QFrame>
#include <QStyle>
#include <QDateTime>
#include <QLocale>
#include <QJsonObject>
#include "DaemonClient.hpp"
#include "Theme.hpp"

class HomePage : public QWidget {
  Q_OBJECT
public:
  HomePage(DaemonClient* client, QWidget* parent = nullptr)
    : QWidget(parent), client_(client) {
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);

    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    auto* body = new QWidget;
    auto* root = new QVBoxLayout(body);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(Theme::spacing(this) * 2);

    // Status
    auto* statusRow = new QHBoxLayout;
    statusRow->setSpacing(Theme::spacing(this) * 2);
    statusIcon_ = new QLabel;
    statusIcon_->setFixedSize(64, 64);
    statusIcon_->setAlignment(Qt::AlignCenter);
    auto* statusCol = new QVBoxLayout;
    statusCol->setSpacing(2);
    statusTitle_ = new QLabel;
    statusTitle_->setFont(Theme::titleFont(statusTitle_->font(), 1.4));
    statusSub_ = Theme::secondaryLabel(QString());
    statusCol->addStretch();
    statusCol->addWidget(statusTitle_);
    statusCol->addWidget(statusSub_);
    statusCol->addStretch();
    statusRow->addWidget(statusIcon_, 0, Qt::AlignTop);
    statusRow->addLayout(statusCol, 1);

    auto* quick = new QPushButton(Theme::icon({"system-search", "edit-find"}), tr("Quick Scan"));
    auto* full = new QPushButton(Theme::icon({"view-refresh"}), tr("Full Scan"));
    quick->setToolTip(tr("Scan common places like Downloads and Desktop"));
    full->setToolTip(tr("Scan the whole system"));
    statusRow->addWidget(quick, 0, Qt::AlignVCenter);
    statusRow->addWidget(full, 0, Qt::AlignVCenter);
    root->addLayout(statusRow);
    connect(quick, &QPushButton::clicked, this, [this] { client_->startScan("quick"); });
    connect(full, &QPushButton::clicked, this, [this] { client_->startScan("full"); });

    // Protection and summary side by side
    auto* mid = new QHBoxLayout;
    mid->setSpacing(Theme::spacing(this) * 2);

    auto* protBox = new QGroupBox(tr("Protection"));
    auto* protLay = new QVBoxLayout(protBox);
    file_ = addToggle(protLay, tr("Real-time file protection"),
                      tr("Watch Downloads, Desktop, and other folders for threats."));
    proc_ = addToggle(protLay, tr("Process monitoring"),
                      tr("Watch new processes for suspicious behavior."));
    net_ = addToggle(protLay, tr("Network monitoring"),
                     tr("Flag risky listening ports and connections."));
    protLay->addStretch();
    mid->addWidget(protBox, 3);

    auto* sumBox = new QGroupBox(tr("Summary"));
    auto* form = new QFormLayout(sumBox);
    threatsVal_ = new QLabel(QStringLiteral("0"));
    quarVal_ = new QLabel(QStringLiteral("0"));
    lastScanVal_ = new QLabel(tr("Never"));
    form->addRow(tr("Active threats:"), threatsVal_);
    form->addRow(tr("In quarantine:"), quarVal_);
    form->addRow(tr("Last scan:"), lastScanVal_);
    mid->addWidget(sumBox, 2);
    root->addLayout(mid);

    auto sync = [this] {
      client_->setProtection(file_->isChecked(), proc_->isChecked(), net_->isChecked());
    };
    connect(file_, &QCheckBox::toggled, this, sync);
    connect(proc_, &QCheckBox::toggled, this, sync);
    connect(net_, &QCheckBox::toggled, this, sync);

    // Recent activity
    auto* actBox = new QGroupBox(tr("Recent Activity"));
    auto* actLay = new QVBoxLayout(actBox);
    activity_ = new QTreeWidget;
    activity_->setHeaderLabels({tr("Time"), tr("Type"), tr("Details")});
    activity_->setRootIsDecorated(false);
    activity_->setUniformRowHeights(true);
    activity_->setSelectionMode(QAbstractItemView::NoSelection);
    activity_->setFocusPolicy(Qt::NoFocus);
    activity_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    activity_->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    activity_->header()->setStretchLastSection(true);
    activity_->setMinimumHeight(160);
    actLay->addWidget(activity_);
    root->addWidget(actBox, 1);

    scroll->setWidget(body);
    outer->addWidget(scroll);

    setOffline();

    connect(client_, &DaemonClient::statusUpdated, this, &HomePage::onStatus);
    connect(client_, &DaemonClient::connectedChanged, this, [this](bool ok) {
      connected_ = ok;
      if (!ok) setOffline();
    });
    connect(client_, &DaemonClient::logEvent, this, [this](const QJsonObject& e) {
      pushActivity(e.value("category").toString(), e.value("message").toString());
    });
    connect(client_, &DaemonClient::threatEvent, this, [this](const QJsonObject& t) {
      pushActivity("threat", t.value("name").toString());
      client_->getStatus();
    });
  }

private:
  QCheckBox* addToggle(QVBoxLayout* lay, const QString& title, const QString& subtitle) {
    auto* box = new QCheckBox(title);
    box->setChecked(true);
    lay->addWidget(box);
    auto* hint = Theme::secondaryLabel(subtitle);
    const int indent = style()->pixelMetric(QStyle::PM_IndicatorWidth, nullptr, box) +
                       style()->pixelMetric(QStyle::PM_CheckBoxLabelSpacing, nullptr, box);
    hint->setContentsMargins(indent, 0, 0, Theme::spacing(this));
    lay->addWidget(hint);
    return box;
  }

  void setStatus(const QStringList& icons, const QString& title, const QString& sub) {
    statusIcon_->setPixmap(Theme::icon(icons).pixmap(64, 64));
    statusTitle_->setText(title);
    statusSub_->setText(sub);
  }

  void setOffline() {
    setStatus({"security-low", "dialog-error"}, tr("Not connected"),
              tr("The Oreon Defense service is not running. Start oreon-defense-daemon to turn on protection."));
  }

  void onStatus(const QJsonObject& s) {
    connected_ = true;
    const bool ok = s.value("protected").toBool(true);
    const QString text = s.value("statusText").toString(ok ? tr("Protected") : tr("At risk"));
    if (ok)
      setStatus({"security-high", "emblem-ok"}, text, tr("Real-time protection is on and no threats are active."));
    else if (text.contains("off", Qt::CaseInsensitive))
      setStatus({"security-medium", "dialog-warning"}, text, tr("Turn on at least one protection option below."));
    else
      setStatus({"security-low", "dialog-warning"}, text, tr("Threats were found. Review them on the Threats page."));

    threatsVal_->setText(QString::number(s.value("threatCount").toVariant().toULongLong()));
    quarVal_->setText(QString::number(s.value("quarantineCount").toVariant().toULongLong()));
    const qint64 last = s.value("lastScan").toVariant().toLongLong();
    if (last <= 0) lastScanVal_->setText(tr("Never"));
    else lastScanVal_->setText(QLocale().toString(QDateTime::fromSecsSinceEpoch(last), QLocale::ShortFormat));

    QSignalBlocker b1(file_), b2(proc_), b3(net_);
    file_->setChecked(s.value("fileRealtime").toBool(true));
    proc_->setChecked(s.value("processWatch").toBool(true));
    net_->setChecked(s.value("networkWatch").toBool(true));
  }

  void pushActivity(const QString& cat, const QString& msg) {
    auto* item = new QTreeWidgetItem({QLocale().toString(QTime::currentTime(), QLocale::ShortFormat),
                                      Theme::capitalized(cat), msg});
    if (cat == QLatin1String("threat"))
      item->setIcon(1, Theme::icon({"dialog-warning"}));
    activity_->insertTopLevelItem(0, item);
    while (activity_->topLevelItemCount() > 40)
      delete activity_->takeTopLevelItem(activity_->topLevelItemCount() - 1);
  }

  DaemonClient* client_;
  bool connected_{false};
  QLabel* statusIcon_;
  QLabel* statusTitle_;
  QLabel* statusSub_;
  QLabel* threatsVal_;
  QLabel* quarVal_;
  QLabel* lastScanVal_;
  QCheckBox* file_;
  QCheckBox* proc_;
  QCheckBox* net_;
  QTreeWidget* activity_;
};
