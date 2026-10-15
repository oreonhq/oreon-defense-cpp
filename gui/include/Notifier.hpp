#pragma once
#include <QObject>
#include <QHash>
#include <QJsonObject>
#include <QStringList>

class Notifier : public QObject {
  Q_OBJECT
public:
  enum class Urgency { Low = 0, Normal = 1, Critical = 2 };

  explicit Notifier(QObject* parent = nullptr);

  bool available() const { return available_; }
  bool supportsActions() const { return actions_; }

  void show(const QString& title, const QString& body, const QString& icon,
            const QList<QPair<QString, QString>>& actions, const QJsonObject& context,
            Urgency urgency = Urgency::Normal, int timeoutMs = 10000);

signals:
  void actionInvoked(const QString& key, const QJsonObject& context);

private slots:
  void onActionInvoked(uint id, const QString& key);
  void onClosed(uint id, uint reason);

private:
  bool available_{false};
  bool actions_{false};
  QHash<uint, QJsonObject> contexts_;
};
