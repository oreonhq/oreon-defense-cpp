#pragma once
#include <QMainWindow>
#include <QJsonObject>
#include <QListWidget>
#include <QStackedWidget>
#include <QLabel>
#include <QCloseEvent>
#include <QElapsedTimer>
#include "DaemonClient.hpp"
#include "TrayIcon.hpp"

class SettingsPage;

class MainWindow : public QMainWindow {
  Q_OBJECT
public:
  explicit MainWindow(QWidget* parent = nullptr);
  void startInTray();

protected:
  void closeEvent(QCloseEvent* event) override;

private:
  void setupUi();
  void setupTray();
  void notifyThreat(const QJsonObject& threat);
  void showDaemonError(const QString& msg);

  DaemonClient* client_{nullptr};
  QListWidget* nav_{nullptr};
  QStackedWidget* stack_{nullptr};
  QLabel* pageTitle_{nullptr};
  TrayIcon* tray_{nullptr};
  SettingsPage* settings_{nullptr};
  bool notifications_{true};
  QElapsedTimer lastErrorShown_;
};
