#include "Notifier.hpp"
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDBusInterface>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDBusReply>
#include <QVariantMap>

static const char* kService = "org.freedesktop.Notifications";
static const char* kPath = "/org/freedesktop/Notifications";
static const char* kIface = "org.freedesktop.Notifications";

Notifier::Notifier(QObject* parent) : QObject(parent) {
  auto bus = QDBusConnection::sessionBus();
  if (!bus.isConnected()) return;
  QDBusInterface iface(kService, kPath, kIface, bus);
  if (!iface.isValid()) return;
  available_ = true;
  QDBusReply<QStringList> caps = iface.call(QStringLiteral("GetCapabilities"));
  actions_ = caps.isValid() && caps.value().contains(QStringLiteral("actions"));
  bus.connect(kService, kPath, kIface, QStringLiteral("ActionInvoked"), this,
              SLOT(onActionInvoked(uint, QString)));
  bus.connect(kService, kPath, kIface, QStringLiteral("NotificationClosed"), this,
              SLOT(onClosed(uint, uint)));
}

void Notifier::show(const QString& title, const QString& body, const QString& icon,
                    const QList<QPair<QString, QString>>& actions, const QJsonObject& context,
                    Urgency urgency, int timeoutMs) {
  if (!available_) return;
  QStringList flat;
  for (const auto& a : actions) flat << a.first << a.second;
  QVariantMap hints;
  hints.insert(QStringLiteral("desktop-entry"), QStringLiteral("oreon-defense"));
  const bool critical = urgency == Urgency::Critical;
  hints.insert(QStringLiteral("urgency"), QVariant::fromValue<uchar>(static_cast<uchar>(urgency)));
  hints.insert(QStringLiteral("category"),
               urgency == Urgency::Low ? QStringLiteral("device") : QStringLiteral("device.error"));
  const int timeout = critical ? 0 : timeoutMs;

  QDBusMessage msg = QDBusMessage::createMethodCall(kService, kPath, kIface, QStringLiteral("Notify"));
  msg << QStringLiteral("Oreon Defense") << uint(0) << icon << title << body << flat
      << hints << timeout;
  auto* w = new QDBusPendingCallWatcher(QDBusConnection::sessionBus().asyncCall(msg), this);
  connect(w, &QDBusPendingCallWatcher::finished, this, [this, w, context] {
    QDBusPendingReply<uint> r = *w;
    if (r.isValid()) {
      contexts_.insert(r.value(), context);
      while (contexts_.size() > 64) contexts_.erase(contexts_.begin());
    }
    w->deleteLater();
  });
}

void Notifier::onActionInvoked(uint id, const QString& key) {
  auto it = contexts_.find(id);
  if (it == contexts_.end()) return;
  const QJsonObject ctx = it.value();
  emit actionInvoked(key, ctx);
}

void Notifier::onClosed(uint id, uint) {
  contexts_.remove(id);
}
