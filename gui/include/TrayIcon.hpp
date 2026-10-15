#pragma once
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QApplication>
#include <QWidget>
#include <QJsonObject>
#include <QIcon>
#include "Theme.hpp"
#include "TrayState.hpp"

class TrayIcon : public QSystemTrayIcon {
  Q_OBJECT
public:
  TrayIcon(QWidget* mainWindow, QObject* parent = nullptr)
    : QSystemTrayIcon(parent), main_(mainWindow) {
    setIcon(QIcon::fromTheme("security-high", QIcon(":/icons/oreon-defense.svg")));
    setToolTip(tr("Oreon Defense"));

    auto* menu = new QMenu;
    showAction_ = menu->addAction(QIcon::fromTheme("window"), tr("Open Oreon Defense"));
    quickAction_ = menu->addAction(QIcon::fromTheme("system-search"), tr("Scan now"));
    updateAction_ = menu->addAction(QIcon::fromTheme("view-refresh"), tr("Check for updates"));
    menu->addSeparator();
    statusAction_ = menu->addAction(tr("Protected"));
    statusAction_->setEnabled(false);
    alertMenu_ = menu->addMenu(Theme::icon({"dialog-warning"}), tr("Latest alert"));
    alertMenu_->setEnabled(false);
    menu->addSeparator();
    quitAction_ = menu->addAction(QIcon::fromTheme("application-exit"), tr("Quit"));
    setContextMenu(menu);

    connect(showAction_, &QAction::triggered, this, &TrayIcon::showMain);
    connect(quitAction_, &QAction::triggered, qApp, &QApplication::quit);
    connect(this, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason r) {
      if (r == QSystemTrayIcon::Trigger || r == QSystemTrayIcon::DoubleClick) showMain();
    });
  }

  QAction* quickScanAction() const { return quickAction_; }
  QAction* updateRulesAction() const { return updateAction_; }

  void setLastAlert(const QString& title, const QList<QPair<QString, QString>>& actions,
                    const QJsonObject& context) {
    alertMenu_->clear();
    auto* head = alertMenu_->addAction(title);
    head->setEnabled(false);
    alertMenu_->addSeparator();
    for (const auto& a : actions) {
      if (a.first == QLatin1String("default")) continue;
      auto* act = alertMenu_->addAction(a.second);
      const QString key = a.first;
      connect(act, &QAction::triggered, this, [this, key, context] { emit alertAction(key, context); });
    }
    alertMenu_->setEnabled(true);
  }

  void setConnected(bool c) { connected_ = c; refresh(); }
  void setStatus(const QJsonObject& s) { status_ = s; refresh(); }
  void setScan(bool running, int percent) { scanning_ = running; scanPercent_ = percent; refresh(); }

  void setProtected(bool ok) {
    connected_ = ok || connected_;
    if (!ok && status_.isEmpty()) connected_ = false;
    refresh();
  }

signals:
  void alertAction(const QString& key, const QJsonObject& context);

private:
  void refresh() {
    const auto p = TrayState::evaluate(status_, connected_, scanning_, scanPercent_);
    setIcon(composed(p));
    setToolTip(tr("Oreon Defense") + QStringLiteral(" - ") + p.tooltip);
    if (statusAction_) statusAction_->setText(p.tooltip);
  }

  QIcon composed(const TrayState::Presentation& p) const {
    QString name = p.baseIcon;
    if (p.disabled || !p.emblem.isEmpty()) {
      if (name == QLatin1String("security-medium") && p.emblem == QLatin1String("view-refresh"))
        name = QStringLiteral("security-medium");
      else if (p.disabled || p.emblem == QLatin1String("emblem-important"))
        name = QStringLiteral("security-low");
    }
    return QIcon::fromTheme(name, QIcon::fromTheme(QStringLiteral("security-high")));
  }

  void showMain() {
    if (main_) { main_->show(); main_->raise(); main_->activateWindow(); }
  }

  QWidget* main_{nullptr};
  QAction* showAction_{nullptr};
  QAction* quickAction_{nullptr};
  QAction* updateAction_{nullptr};
  QAction* statusAction_{nullptr};
  QAction* quitAction_{nullptr};
  QMenu* alertMenu_{nullptr};

  QJsonObject status_;
  bool connected_{false};
  bool scanning_{false};
  int scanPercent_{-1};
};
