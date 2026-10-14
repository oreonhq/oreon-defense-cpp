#pragma once
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QApplication>
#include <QWidget>

class TrayIcon : public QSystemTrayIcon {
  Q_OBJECT
public:
  TrayIcon(QWidget* mainWindow, QObject* parent = nullptr)
    : QSystemTrayIcon(parent), main_(mainWindow) {
    setIcon(QIcon::fromTheme("security-high", QIcon(":/icons/oreon-defense.svg")));
    setToolTip(tr("Oreon Defense"));

    auto* menu = new QMenu;
    showAction_ = menu->addAction(QIcon::fromTheme("window"), tr("Open Oreon Defense"));
    quickAction_ = menu->addAction(QIcon::fromTheme("system-search"), tr("Quick Scan"));
    menu->addSeparator();
    quitAction_ = menu->addAction(QIcon::fromTheme("application-exit"), tr("Quit"));
    setContextMenu(menu);

    connect(showAction_, &QAction::triggered, this, [this] {
      if (main_) { main_->show(); main_->raise(); main_->activateWindow(); }
    });
    connect(quitAction_, &QAction::triggered, qApp, &QApplication::quit);
    connect(this, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason r) {
      if (r == QSystemTrayIcon::Trigger || r == QSystemTrayIcon::DoubleClick) {
        if (main_) { main_->show(); main_->raise(); main_->activateWindow(); }
      }
    });
  }

  QAction* quickScanAction() const { return quickAction_; }

  void setProtected(bool ok) {
    if (ok) {
      setIcon(QIcon::fromTheme("security-high", QIcon::fromTheme("emblem-ok")));
      setToolTip(tr("Oreon Defense: Protected"));
    } else {
      setIcon(QIcon::fromTheme("security-low", QIcon::fromTheme("emblem-important")));
      setToolTip(tr("Oreon Defense: At risk"));
    }
  }

private:
  QWidget* main_{nullptr};
  QAction* showAction_{nullptr};
  QAction* quickAction_{nullptr};
  QAction* quitAction_{nullptr};
};
