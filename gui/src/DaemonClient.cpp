#include "DaemonClient.hpp"
#include <QJsonDocument>
#include <QStandardPaths>
#include <QDir>
#include <QFileInfo>
#include <unistd.h>

QString defaultGuiSocketPath() {
  const QString sysSock = QStringLiteral("/run/oreon-defense/daemon.sock");
  if (QFileInfo::exists(sysSock))
    return sysSock;
  if (geteuid() == 0)
    return sysSock;
  const QString home = QDir::homePath();
  return home + "/.local/share/oreon-defense/daemon.sock";
}

DaemonClient::DaemonClient(QObject* parent) : QObject(parent) {
  sock_ = new QLocalSocket(this);
  reconnect_ = new QTimer(this);
  reconnect_->setInterval(1500);
  connect(sock_, &QLocalSocket::connected, this, &DaemonClient::onConnected);
  connect(sock_, &QLocalSocket::disconnected, this, &DaemonClient::onDisconnected);
  connect(sock_, &QLocalSocket::readyRead, this, &DaemonClient::onReadyRead);
  connect(reconnect_, &QTimer::timeout, this, &DaemonClient::tryReconnect);
}

void DaemonClient::connectToDaemon(const QString& path) {
  socketPath_ = path.isEmpty() ? defaultGuiSocketPath() : path;
  if (sock_->state() != QLocalSocket::UnconnectedState)
    sock_->abort();
  sock_->connectToServer(socketPath_);
  if (!reconnect_->isActive()) reconnect_->start();
}

bool DaemonClient::isConnected() const {
  return sock_->state() == QLocalSocket::ConnectedState;
}

void DaemonClient::tryReconnect() {
  if (isConnected()) return;
  sock_->abort();
  sock_->connectToServer(socketPath_);
}

void DaemonClient::onConnected() {
  emit connectedChanged(true);
  getStatus();
  getThreats();
  getQuarantine();
  getNetwork();
  getHistory();
  getConfig();
  getBlocklist();
}

void DaemonClient::onDisconnected() {
  emit connectedChanged(false);
}

QString DaemonClient::nextId() {
  return QString::number(++idSeq_);
}

void DaemonClient::call(const QString& method, const QJsonObject& params, ReplyFn cb) {
  if (!isConnected()) {
    const QString err = QStringLiteral("not connected");
    emit errorMessage(err);
    if (cb) cb(false, {}, err);
    return;
  }
  const QString id = nextId();
  if (cb) pending_.insert(id, std::move(cb));
  QJsonObject req{{"id", id}, {"method", method}, {"params", params}};
  QByteArray line = QJsonDocument(req).toJson(QJsonDocument::Compact);
  line.append('\n');
  sock_->write(line);
  sock_->flush();
}

void DaemonClient::onReadyRead() {
  buffer_.append(sock_->readAll());
  int idx;
  while ((idx = buffer_.indexOf('\n')) >= 0) {
    QByteArray line = buffer_.left(idx);
    buffer_.remove(0, idx + 1);
    handleLine(line);
  }
}

void DaemonClient::handleLine(const QByteArray& line) {
  QJsonParseError err;
  QJsonDocument doc = QJsonDocument::fromJson(line, &err);
  if (err.error != QJsonParseError::NoError || !doc.isObject()) return;
  QJsonObject obj = doc.object();

  if (obj.contains("event")) {
    const QString ev = obj.value("event").toString();
    const QJsonObject data = obj.value("data").toObject();
    if (ev == "threat") emit threatEvent(data);
    else if (ev == "scanProgress") emit scanProgress(data);
    else if (ev == "scanDone") emit scanDone(data);
    else if (ev == "status") emit statusUpdated(data);
    else if (ev == "log") emit logEvent(data);
    else if (ev == "network") emit networkEvent(data);
    else if (ev == "rulesUpdate") emit rulesUpdated(data);
    else if (ev == "blocklist") getBlocklist();
    return;
  }

  const QString id = obj.value("id").toString();
  const bool ok = obj.value("ok").toBool();
  const QJsonObject result = obj.value("result").toObject();
  const QString error = obj.value("error").toString();
  if (pending_.contains(id)) {
    auto cb = pending_.take(id);
    if (cb) cb(ok, result, error);
  }
  if (!ok && !error.isEmpty()) {
    if (obj.value("code").toString() == QLatin1String("EPERM"))
      emit errorMessage(tr("You are not allowed to do that. %1").arg(error));
    else
      emit errorMessage(error);
  }
}

void DaemonClient::getStatus() {
  call("getStatus", {}, [this](bool ok, const QJsonObject& r, const QString&) {
    if (ok) emit statusUpdated(r);
  });
}

void DaemonClient::setProtection(bool fileRt, bool proc, bool net) {
  call("setProtection", {{"fileRealtime", fileRt}, {"processWatch", proc}, {"networkWatch", net}},
       [this](bool ok, const QJsonObject& r, const QString&) {
         if (ok) emit statusUpdated(r);
       });
}

void DaemonClient::startScan(const QString& type, const QStringList& paths) {
  QJsonObject p{{"type", type}};
  if (!paths.isEmpty()) {
    QJsonArray arr;
    for (const auto& x : paths) arr.append(x);
    p["paths"] = arr;
  }
  call("startScan", p);
}

void DaemonClient::cancelScan() { call("cancelScan"); }

void DaemonClient::getThreats() {
  call("getThreats", {}, [this](bool ok, const QJsonObject& r, const QString&) {
    if (ok) emit threatsList(r.value("threats").toArray());
  });
}

void DaemonClient::getQuarantine() {
  call("getQuarantine", {}, [this](bool ok, const QJsonObject& r, const QString&) {
    if (ok) emit quarantineList(r.value("items").toArray());
  });
}

void DaemonClient::quarantinePath(const QString& path, const QString& id) {
  QJsonObject p;
  if (!path.isEmpty()) p["path"] = path;
  if (!id.isEmpty()) p["id"] = id;
  call("quarantine", p, [this](bool ok, const QJsonObject&, const QString& err) {
    emit actionDone(QStringLiteral("quarantine"), ok, err);
    getQuarantine();
    getThreats();
    getStatus();
  });
}

void DaemonClient::restore(const QString& id) {
  call("restore", {{"id", id}}, [this](bool ok, const QJsonObject&, const QString& err) {
    emit actionDone(QStringLiteral("restore"), ok, err);
    getThreats();
    getQuarantine();
    getStatus();
  });
}

void DaemonClient::deleteQuarantine(const QString& id) {
  call("deleteQuarantine", {{"id", id}}, [this](bool ok, const QJsonObject&, const QString& err) {
    emit actionDone(QStringLiteral("delete"), ok, err);
    getThreats();
    getQuarantine();
    getStatus();
  });
}

void DaemonClient::allowPath(const QString& path) {
  call("allow", {{"path", path}}, [this](bool ok, const QJsonObject&, const QString& err) {
    emit actionDone(QStringLiteral("allow"), ok, err);
    getThreats();
    getStatus();
  });
}

void DaemonClient::getNetwork() {
  call("getNetwork", {}, [this](bool ok, const QJsonObject& r, const QString&) {
    if (ok) emit networkList(r.value("entries").toArray());
  });
}

void DaemonClient::getHistory(const QString& search) {
  call("getHistory", {{"search", search}, {"limit", 500}},
       [this](bool ok, const QJsonObject& r, const QString&) {
         if (ok) emit historyList(r.value("events").toArray());
       });
}

void DaemonClient::getConfig() {
  call("getConfig", {}, [this](bool ok, const QJsonObject& r, const QString&) {
    if (ok) emit configLoaded(r);
  });
}

void DaemonClient::setConfig(const QJsonObject& cfg) {
  call("setConfig", cfg, [this](bool ok, const QJsonObject&, const QString& err) {
    emit actionDone(QStringLiteral("setConfig"), ok, err);
    if (ok) getConfig();
  });
}

void DaemonClient::updateRules(const QString& path) {
  QJsonObject p;
  if (!path.isEmpty()) p["path"] = path;
  else p["reloadOnly"] = true;
  call("updateRules", p, [this](bool ok, const QJsonObject&, const QString& err) {
    emit actionDone(QStringLiteral("reloadRules"), ok, err);
    if (ok) getStatus();
  });
}

void DaemonClient::reloadRules() { updateRules(); }

void DaemonClient::updateRulesNow(bool force) {
  call("updateRules", {{"force", force}}, [this](bool ok, const QJsonObject&, const QString& err) {
    emit actionDone(QStringLiteral("updateRules"), ok, err);
  });
}

void DaemonClient::setOptions(const QJsonObject& opts) {
  call("setOptions", opts, [this](bool ok, const QJsonObject& r, const QString& err) {
    emit actionDone(QStringLiteral("setOptions"), ok, err);
    if (ok) emit statusUpdated(r);
    getConfig();
  });
}

void DaemonClient::getBlocklist() {
  call("getBlocklist", {}, [this](bool ok, const QJsonObject& r, const QString&) {
    if (ok) emit blocklistList(r.value("entries").toArray(), r.value("active").toBool());
  });
}

void DaemonClient::blockIp(const QString& ip, const QString& reason) {
  QJsonObject p{{"ip", ip}};
  if (!reason.isEmpty()) p["reason"] = reason;
  call("blockIp", p, [this](bool ok, const QJsonObject&, const QString& err) {
    emit actionDone(QStringLiteral("block"), ok, err);
    getBlocklist();
  });
}

void DaemonClient::unblockIp(const QString& ip) {
  call("unblockIp", {{"ip", ip}}, [this](bool ok, const QJsonObject&, const QString& err) {
    emit actionDone(QStringLiteral("unblock"), ok, err);
    getBlocklist();
  });
}

void DaemonClient::killProcess(int pid) {
  call("killProcess", {{"pid", pid}}, [this](bool ok, const QJsonObject&, const QString& err) {
    emit actionDone(QStringLiteral("kill"), ok, err);
    getThreats();
  });
}
