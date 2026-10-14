#pragma once
#include <QObject>
#include <QLocalSocket>
#include <QJsonObject>
#include <QJsonArray>
#include <QTimer>
#include <QHash>
#include <functional>

class DaemonClient : public QObject {
  Q_OBJECT
public:
  explicit DaemonClient(QObject* parent = nullptr);

  void connectToDaemon(const QString& path = QString());
  bool isConnected() const;
  QString socketPath() const { return socketPath_; }

  using ReplyFn = std::function<void(bool ok, const QJsonObject& result, const QString& error)>;

  void call(const QString& method, const QJsonObject& params = {}, ReplyFn cb = {});
  void getStatus();
  void setProtection(bool fileRt, bool proc, bool net);
  void startScan(const QString& type, const QStringList& paths = {});
  void cancelScan();
  void getThreats();
  void getQuarantine();
  void quarantinePath(const QString& path, const QString& id = {});
  void restore(const QString& id);
  void deleteQuarantine(const QString& id);
  void allowPath(const QString& path);
  void getNetwork();
  void getHistory(const QString& search = {});
  void getConfig();
  void setConfig(const QJsonObject& cfg);
  void updateRules(const QString& path = {});

signals:
  void connectedChanged(bool connected);
  void statusUpdated(const QJsonObject& status);
  void threatEvent(const QJsonObject& threat);
  void scanProgress(const QJsonObject& progress);
  void scanDone(const QJsonObject& progress);
  void logEvent(const QJsonObject& event);
  void networkEvent(const QJsonObject& entry);
  void threatsList(const QJsonArray& threats);
  void quarantineList(const QJsonArray& items);
  void networkList(const QJsonArray& entries);
  void historyList(const QJsonArray& events);
  void configLoaded(const QJsonObject& cfg);
  void errorMessage(const QString& msg);

private slots:
  void onConnected();
  void onDisconnected();
  void onReadyRead();
  void tryReconnect();

private:
  void handleLine(const QByteArray& line);
  QString nextId();

  QLocalSocket* sock_{nullptr};
  QString socketPath_;
  QByteArray buffer_;
  QHash<QString, ReplyFn> pending_;
  QTimer* reconnect_{nullptr};
  quint64 idSeq_{0};
};

QString defaultGuiSocketPath();
