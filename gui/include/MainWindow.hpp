#pragma once
#include <QMainWindow>
#include <QJsonObject>
#include <QListWidget>
#include <QStackedWidget>
#include <QLabel>
#include <QCloseEvent>
#include <QElapsedTimer>
#include <QTimer>
#include "AlertBatcher.hpp"
#include "DaemonClient.hpp"
#include "TrayIcon.hpp"
#include "Notifier.hpp"

class SettingsPage;

class MainWindow : public QMainWindow {
  Q_OBJECT
public:
  explicit MainWindow(QWidget* parent = nullptr);
  void startInTray();
  void showMain();

protected:
  void closeEvent(QCloseEvent* event) override;

private:
  void setupUi();
  void setupTray();
  void notifyThreat(const QJsonObject& threat);
  void flushAlerts();
  void showThreatAlert(const AlertBatcher::Alert& a);
  void notifyNetwork(const QJsonObject& entry);
  void raiseAlert(const QString& title, const QString& body, const QString& icon,
                  const QList<QPair<QString, QString>>& actions, const QJsonObject& ctx,
                  Notifier::Urgency urgency, int timeoutMs = 10000);
  void handleAlertAction(const QString& key, const QJsonObject& ctx);
  void showDaemonError(const QString& msg);

  DaemonClient* client_{nullptr};
  QListWidget* nav_{nullptr};
  QStackedWidget* stack_{nullptr};
  TrayIcon* tray_{nullptr};
  Notifier* notifier_{nullptr};
  SettingsPage* settings_{nullptr};
  bool notifications_{true};
  QElapsedTimer lastErrorShown_;
  AlertBatcher batcher_;
  QTimer* batchTimer_{nullptr};
  QElapsedTimer clock_;
  QHash<QString, qint64> networkSeen_;
};
