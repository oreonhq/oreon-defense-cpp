#pragma once
#include <QWidget>
#include <QPlainTextEdit>
#include <QTimeEdit>
#include <QComboBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QCheckBox>
#include <QFileDialog>
#include <QMessageBox>
#include <QJsonObject>
#include <QJsonArray>
#include <QTime>
#include <QApplication>
#include "DaemonClient.hpp"
#include "Theme.hpp"

class SettingsPage : public QWidget {
  Q_OBJECT
public:
  SettingsPage(DaemonClient* client, QWidget* parent = nullptr)
    : QWidget(parent), client_(client) {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(Theme::spacing(this) * 2);

    // Exclusions
    auto* exclBox = new QGroupBox(tr("Exclusions"));
    auto* exclLay = new QVBoxLayout(exclBox);
    exclLay->addWidget(Theme::secondaryLabel(tr("Files and folders listed here are never scanned. One path per line.")));
    excl_ = new QPlainTextEdit;
    excl_->setPlaceholderText(tr("/home/user/projects/samples"));
    excl_->setTabChangesFocus(true);
    exclLay->addWidget(excl_, 1);
    auto* addRow = new QHBoxLayout;
    auto* addFolder = new QPushButton(Theme::icon({"list-add"}), tr("Add Folder..."));
    addRow->addWidget(addFolder);
    addRow->addStretch();
    exclLay->addLayout(addRow);
    root->addWidget(exclBox, 1);

    // Schedule and notifications
    auto* genBox = new QGroupBox(tr("General"));
    auto* form = new QFormLayout(genBox);
    scheduleType_ = new QComboBox;
    scheduleType_->addItems({tr("Off"), tr("Daily")});
    time_ = new QTimeEdit;
    time_->setDisplayFormat(QStringLiteral("HH:mm"));
    time_->setTime(QTime(3, 0));
    notify_ = new QCheckBox(tr("Show a notification when a threat is found"));
    notify_->setChecked(true);
    form->addRow(tr("Scheduled scan:"), scheduleType_);
    form->addRow(tr("Scan time:"), time_);
    form->addRow(tr("Notifications:"), notify_);
    root->addWidget(genBox);

    // Detection rules
    auto* rulesBox = new QGroupBox(tr("Detection Rules"));
    auto* rulesLay = new QHBoxLayout(rulesBox);
    rulesLay->addWidget(Theme::secondaryLabel(tr("Reload the rule files after editing or updating them.")), 1);
    auto* rules = new QPushButton(Theme::icon({"view-refresh"}), tr("Reload Rules"));
    rulesLay->addWidget(rules);
    root->addWidget(rulesBox);

    // Footer
    auto* footer = new QHBoxLayout;
    auto* about = Theme::secondaryLabel(
      tr("Oreon Defense %1  |  <a href=\"https://oreonhq.com\">oreonhq.com</a>")
        .arg(QApplication::applicationVersion()));
    about->setTextFormat(Qt::RichText);
    about->setOpenExternalLinks(true);
    about->setWordWrap(false);
    auto* save = new QPushButton(Theme::icon({"dialog-ok-apply", "document-save"}), tr("Apply"));
    footer->addWidget(about);
    footer->addStretch();
    footer->addWidget(save);
    root->addLayout(footer);

    auto updateTime = [this] { time_->setEnabled(scheduleType_->currentIndex() == 1); };
    connect(scheduleType_, &QComboBox::currentIndexChanged, this, updateTime);
    updateTime();

    connect(addFolder, &QPushButton::clicked, this, [this] {
      const QString dir = QFileDialog::getExistingDirectory(this, tr("Exclude Folder"));
      if (dir.isEmpty()) return;
      QString text = excl_->toPlainText().trimmed();
      if (!text.isEmpty()) text += '\n';
      excl_->setPlainText(text + dir);
    });
    connect(client_, &DaemonClient::configLoaded, this, &SettingsPage::load);
    connect(save, &QPushButton::clicked, this, &SettingsPage::save);
    connect(rules, &QPushButton::clicked, this, [this] { client_->updateRules(); });
    connect(notify_, &QCheckBox::toggled, this, &SettingsPage::notificationsToggled);
  }

  bool notificationsEnabled() const { return notify_->isChecked(); }

signals:
  void notificationsToggled(bool enabled);

private:
  void load(const QJsonObject& cfg) {
    QStringList excl;
    for (const auto& v : cfg.value("exclusions").toArray())
      excl << v.toString();
    excl_->setPlainText(excl.join('\n'));
    const QString st = cfg.value("scheduleType").toString("none");
    scheduleType_->setCurrentIndex(st == "daily" ? 1 : 0);
    time_->setTime(QTime(cfg.value("scheduleHour").toInt(3), cfg.value("scheduleMinute").toInt(0)));
  }

  void save() {
    QJsonObject cfg;
    QJsonArray excl;
    for (const QString& line : excl_->toPlainText().split('\n', Qt::SkipEmptyParts)) {
      const QString t = line.trimmed();
      if (!t.isEmpty()) excl.append(t);
    }
    cfg["exclusions"] = excl;
    cfg["scheduleType"] = scheduleType_->currentIndex() == 1 ? "daily" : "none";
    cfg["scheduleHour"] = time_->time().hour();
    cfg["scheduleMinute"] = time_->time().minute();
    client_->setConfig(cfg);
    emit notificationsToggled(notify_->isChecked());
    QMessageBox::information(this, tr("Settings"), tr("Settings saved."));
  }

  DaemonClient* client_;
  QPlainTextEdit* excl_;
  QComboBox* scheduleType_;
  QTimeEdit* time_;
  QCheckBox* notify_;
};
