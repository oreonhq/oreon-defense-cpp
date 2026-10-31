#include "MainWindow.hpp"
#include "pages/HomePage.hpp"
#include "pages/ScansPage.hpp"
#include "pages/ThreatsPage.hpp"
#include "pages/HistoryPage.hpp"
#include "pages/SettingsPage.hpp"
#include "Theme.hpp"
#include "NotifyText.hpp"
#include <QDesktopServices>
#include <QUrl>
#include <QFileInfo>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QFrame>
#include <QDBusInterface>
#include <QMessageBox>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
  client_ = new DaemonClient(this);
  notifier_ = new Notifier(this);
  clock_.start();
  batchTimer_ = new QTimer(this);
  batchTimer_->setSingleShot(true);
  connect(batchTimer_, &QTimer::timeout, this, &MainWindow::flushAlerts);
  setupUi();
  setupTray();
  setWindowTitle(tr("Oreon Defense"));
  setWindowIcon(QIcon::fromTheme("oreon-defense", QIcon(QStringLiteral(":/icons/oreon-defense.svg"))));
  resize(1000, 680);
  // offline until first successful connect
  emit client_->connectedChanged(false);
  if (tray_) tray_->setConnected(false);
  client_->connectToDaemon();
}

void MainWindow::startInTray() {
  // window stays hidden; tray already shown in setupTray
  if (tray_) tray_->show();
}

void MainWindow::setupUi() {
  setStatusBar(nullptr);

  auto* central = new QWidget(this);
  auto* lay = new QHBoxLayout(central);
  lay->setContentsMargins(0, 0, 0, 0);
  lay->setSpacing(0);

  nav_ = new QListWidget;
  nav_->setFrameShape(QFrame::NoFrame);
  nav_->setIconSize(QSize(22, 22));
  nav_->setUniformItemSizes(true);
  nav_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  nav_->setSelectionMode(QAbstractItemView::SingleSelection);
  nav_->setSpacing(1);

  struct NavItem { QString text; QStringList icons; };
  const QList<NavItem> items = {
    {tr("Overview"), {"go-home", "user-home"}},
    {tr("Scan"), {"system-search", "edit-find"}},
    {tr("Threats"), {"security-medium-symbolic", "security-medium"}},
    {tr("History"), {"view-history", "document-open-recent"}},
    {tr("Settings"), {"configure", "preferences-system"}},
  };
  const int sp = Theme::spacing(nav_);
  for (const auto& it : items) {
    auto* item = new QListWidgetItem(Theme::icon(it.icons), it.text);
    item->setSizeHint(QSize(0, nav_->iconSize().height() + 2 * sp + 4));
    nav_->addItem(item);
  }
  int navWidth = 0;
  for (const auto& it : items)
    navWidth = qMax(navWidth, nav_->fontMetrics().horizontalAdvance(it.text));
  nav_->setFixedWidth(qMax(160, navWidth + nav_->iconSize().width() + 48));

  auto* side = new QWidget;
  side->setBackgroundRole(QPalette::Base);
  side->setAutoFillBackground(true);
  auto* sideLay = new QVBoxLayout(side);
  sideLay->setContentsMargins(sp, sp, sp, sp);
  sideLay->addWidget(nav_);

  auto* sep = new QFrame;
  sep->setFrameShape(QFrame::VLine);
  sep->setFrameShadow(QFrame::Sunken);

  stack_ = new QStackedWidget;
  stack_->addWidget(new HomePage(client_));
  stack_->addWidget(new ScansPage(client_));
  stack_->addWidget(new ThreatsPage(client_));
  stack_->addWidget(new HistoryPage(client_));
  settings_ = new SettingsPage(client_);
  stack_->addWidget(settings_);
  const int m = Theme::pageMargin(this);
  for (int i = 0; i < stack_->count(); ++i) {
    if (auto* l = stack_->widget(i)->layout())
      l->setContentsMargins(m, m, m, m);
  }

  lay->addWidget(side);
  lay->addWidget(sep);
  lay->addWidget(stack_, 1);
  setCentralWidget(central);
  nav_->setCurrentRow(0);

  connect(nav_, &QListWidget::currentRowChanged, stack_, &QStackedWidget::setCurrentIndex);
  connect(client_, &DaemonClient::connectedChanged, this, [this](bool ok) {
    if (tray_) tray_->setConnected(ok);
  });
  connect(client_, &DaemonClient::statusUpdated, this, [this](const QJsonObject& s) {
    if (tray_) {
      tray_->setConnected(client_->isConnected());
      tray_->setStatus(s);
    }
  });
  connect(client_, &DaemonClient::scanProgress, this, [this](const QJsonObject& p) {
    if (!tray_) return;
    const double total = p.value("filesTotal").toDouble(0);
    const double done = p.value("filesScanned").toDouble(0);
    int pct = total > 0 ? int(done * 100.0 / total) : -1;
    tray_->setScan(p.value("running").toBool(true), pct);
  });
  connect(client_, &DaemonClient::scanDone, this, [this](const QJsonObject&) {
    if (tray_) tray_->setScan(false, -1);
  });
  connect(client_, &DaemonClient::threatEvent, this, &MainWindow::notifyThreat);
  connect(client_, &DaemonClient::networkEvent, this, &MainWindow::notifyNetwork);
  connect(client_, &DaemonClient::actionDone, this, [this](const QString& what, bool ok, const QString& error) {
    if (ok) return;
    QString title;
    if (what == QLatin1String("quarantine")) title = tr("Quarantine failed");
    else if (what == QLatin1String("restore")) title = tr("Restore failed");
    else if (what == QLatin1String("delete")) title = tr("Delete failed");
    else if (what == QLatin1String("allow")) title = tr("Allow failed");
    else return;
    QMessageBox::warning(this, title, error.isEmpty() ? tr("The service could not do this.") : error);
  });
  connect(notifier_, &Notifier::actionInvoked, this, &MainWindow::handleAlertAction);
  connect(client_, &DaemonClient::rulesUpdated, this, [this](const QJsonObject& r) {
    client_->getStatus();
    if (!r.value("lastError").toString().isEmpty() && isVisible())
      showDaemonError(tr("Rule update failed: %1").arg(r.value("lastError").toString()));
  });
  connect(client_, &DaemonClient::errorMessage, this, &MainWindow::showDaemonError);
  connect(settings_, &SettingsPage::notificationsToggled, this, [this](bool on) {
    notifications_ = on;
  });
}

void MainWindow::setupTray() {
  if (!QSystemTrayIcon::isSystemTrayAvailable()) return;
  tray_ = new TrayIcon(this, this);
  tray_->show();
  connect(tray_->quickScanAction(), &QAction::triggered, this, [this] {
    client_->startScan("quick");
  });
  connect(tray_->updateRulesAction(), &QAction::triggered, this, [this] {
    client_->updateRulesNow();
  });
  connect(tray_, &TrayIcon::alertAction, this, &MainWindow::handleAlertAction);
}

void MainWindow::showMain() {
  if (isMinimized()) showNormal();
  show();
  raise();
  activateWindow();
}

void MainWindow::showDaemonError(const QString& msg) {
  // avoid spam when several buttons fire while offline
  if (lastErrorShown_.isValid() && lastErrorShown_.elapsed() < 2500)
    return;
  lastErrorShown_.restart();
  const QString title = tr("Oreon Defense");
  QString body = msg;
  if (body.isEmpty() || body == QLatin1String("not connected"))
    body = tr("Can't reach the Oreon Defense service. Make sure oreon-defense-daemon is running.");
  if (!isVisible() && tray_ && tray_->isVisible()) {
    tray_->showMessage(title, body, QSystemTrayIcon::Warning, 4000);
    return;
  }
  QMessageBox::warning(this, title, body);
}

void MainWindow::raiseAlert(const QString& title, const QString& body, const QString& icon,
                            const QList<QPair<QString, QString>>& actions, const QJsonObject& ctx,
                            Notifier::Urgency urgency, int timeoutMs) {
  if (tray_) tray_->setLastAlert(title, actions, ctx);
  if (!notifications_) return;
  if (notifier_->available()) {
    notifier_->show(title, body, Theme::iconName({icon}, QStringLiteral("oreon-defense")), actions, ctx, urgency, timeoutMs);
  } else if (tray_) {
    const auto kind = urgency == Notifier::Urgency::Low ? QSystemTrayIcon::Information
                                                        : QSystemTrayIcon::Warning;
    tray_->showMessage(title, body, kind, urgency == Notifier::Urgency::Low ? 5000 : 8000);
  }
}

void MainWindow::notifyThreat(const QJsonObject& threat) {
  if (batcher_.add(threat, clock_.elapsed())) batchTimer_->start(AlertBatcher::kWindowMs);
}

void MainWindow::flushAlerts() {
  for (const auto& a : batcher_.flush(clock_.elapsed())) showThreatAlert(a);
}

void MainWindow::showThreatAlert(const AlertBatcher::Alert& a) {
  QList<QPair<QString, QString>> actions;
  actions.append({QStringLiteral("default"), tr("Open Oreon Defense")});

  if (a.summary) {
    QJsonObject ctx;
    ctx["kind"] = QStringLiteral("summary");
    NotifyText::Text t;
    if (a.strong) {
      t = NotifyText::summary(a.count, a.quarantined, a.blocked, a.killed);
    } else {
      t.title = tr("Some files look unusual");
      t.body = tr("%n file(s) look unusual. Nothing was blocked or moved.", "", a.count);
    }
    actions.append({QStringLiteral("open"), tr("Show details")});
    raiseAlert(t.title, t.body,
               a.strong ? QStringLiteral("security-low") : QStringLiteral("dialog-information"),
               actions, ctx, a.strong ? Notifier::Urgency::Critical : Notifier::Urgency::Low,
               a.strong ? 10000 : 6000);
    return;
  }

  const QJsonObject& threat = a.threat;
  const QString name = threat.value("name").toString();
  const QString path = threat.value("path").toString();
  const int action = threat.value("action").toInt(0);
  const QString kind = threat.value("kind").toString("file");
  const QString sev = threat.value("severity").toString();
  const bool critical = a.strong && (sev == QLatin1String("critical") || sev == QLatin1String("high"));

  NotifyText::Text t;
  QString icon = a.strong ? QStringLiteral("security-low") : QStringLiteral("dialog-information");

  if (kind == QLatin1String("process")) {
    const int pid = threat.value("pid").toInt();
    if (action == 6) {
      t = NotifyText::processKilled(threat);
      actions.append({QStringLiteral("allow"), tr("Allow")});
    } else {
      t.title = tr("A program looks harmful");
      t.body = name.isEmpty() ? tr("A program looks harmful.") : tr("%1 looks harmful.").arg(name);
      actions.append({QStringLiteral("kill"), tr("Stop it")});
      actions.append({QStringLiteral("allow"), tr("Allow")});
    }
    Q_UNUSED(pid);
  } else if (kind == QLatin1String("guard")) {
    t.title = name.isEmpty() ? tr("Something looked unsafe") : name;
    t.body = threat.value("description").toString();
    actions.append({QStringLiteral("open"), tr("Show details")});
    icon = QStringLiteral("security-low");
  } else if (action == 1) {
    t = NotifyText::quarantined(threat);
    actions.append({QStringLiteral("open-folder"), tr("Open")});
    actions.append({QStringLiteral("delete"), tr("Delete")});
    actions.append({QStringLiteral("allow"), tr("Restore")});
  } else if (action == 5) {
    t = NotifyText::blocked(threat);
    actions.append({QStringLiteral("quarantine"), tr("Move to quarantine")});
    actions.append({QStringLiteral("allow"), tr("Allow")});
  } else if (a.strong) {
    t.title = tr("Oreon Defense found a dangerous file");
    t.body = tr("%1 is %2.").arg(NotifyText::fileName(path), NotifyText::humanThreat(name));
    actions.append({QStringLiteral("quarantine"), tr("Move to quarantine")});
    actions.append({QStringLiteral("allow"), tr("Allow")});
  } else {
    t = NotifyText::suspicious(threat);
    actions.append({QStringLiteral("allow"), tr("Allow")});
    actions.append({QStringLiteral("open"), tr("Show details")});
  }
  if (!actions.contains({QStringLiteral("open"), tr("Show details")}))
    actions.append({QStringLiteral("open"), tr("Show details")});
  Notifier::Urgency urgency = critical ? Notifier::Urgency::Critical
                              : a.strong ? Notifier::Urgency::Normal
                                         : Notifier::Urgency::Low;
  raiseAlert(t.title, t.body, icon, actions, threat, urgency, a.strong ? 10000 : 6000);
}

void MainWindow::notifyNetwork(const QJsonObject& entry) {
  const QString ip = entry.value("remoteIp").toString();
  const QString risk = entry.value("risk").toString();
  if (ip.isEmpty() || risk == QLatin1String("blocked")) return;
  const QString key = entry.value("process").toString() + QLatin1Char('|') + ip;
  const qint64 now = clock_.elapsed();
  auto seen = networkSeen_.find(key);
  if (seen != networkSeen_.end() && now - seen.value() < 5 * 60 * 1000) return;
  if (networkSeen_.size() > 1024) networkSeen_.clear();
  networkSeen_.insert(key, now);
  const QString title = tr("Oreon Defense noticed a risky connection");
  const QString body = tr("%1 connected to %2.")
    .arg(entry.value("process").toString())
    .arg(entry.value("remoteAddr").toString());
  QList<QPair<QString, QString>> actions{
    {QStringLiteral("default"), tr("Open Oreon Defense")},
    {QStringLiteral("block"), tr("Block")},
  };
  if (entry.value("pid").toInt() > 1) actions.append({QStringLiteral("kill"), tr("Kill process")});
  actions.append({QStringLiteral("open"), tr("Open Oreon Defense")});
  QJsonObject ctx = entry;
  ctx["kind"] = QStringLiteral("network");
  raiseAlert(title, body, QStringLiteral("network-error"), actions, ctx, Notifier::Urgency::Normal);
}

void MainWindow::handleAlertAction(const QString& key, const QJsonObject& ctx) {
  const QString path = ctx.value("path").toString();
  const QString id = ctx.value("id").toString();
  const QString qid = ctx.value("quarantineId").toString();
  if (key == QLatin1String("default")) {
    showMain();
  } else if (key == QLatin1String("open")) {
    showMain();
    const QString details = ctx.value("description").toString();
    if (!details.isEmpty()) {
      QMessageBox box(this);
      box.setIcon(QMessageBox::Information);
      box.setWindowTitle(tr("Details"));
      box.setText(ctx.value("name").toString());
      box.setInformativeText(path);
      box.setDetailedText(details);
      box.setStandardButtons(QMessageBox::Close);
      box.exec();
    }
  } else if (key == QLatin1String("open-folder")) {
    const QString folder = QFileInfo(path).absolutePath();
    if (!folder.isEmpty())
      QDesktopServices::openUrl(QUrl::fromLocalFile(folder));
  } else if (key == QLatin1String("quarantine")) {
    client_->quarantinePath(path, id);
  } else if (key == QLatin1String("delete")) {
    if (!qid.isEmpty()) client_->deleteQuarantine(qid);
  } else if (key == QLatin1String("allow")) {
    if (!qid.isEmpty()) client_->restore(qid);
    else if (!path.isEmpty()) client_->allowPath(path);
  } else if (key == QLatin1String("kill")) {
    const int pid = ctx.value("pid").toInt();
    if (pid > 1) client_->killProcess(pid);
  } else if (key == QLatin1String("block")) {
    const QString ip = ctx.value("remoteIp").toString();
    if (!ip.isEmpty())
      client_->blockIp(ip, tr("Blocked from a notification (%1)").arg(ctx.value("process").toString()));
  }
}

void MainWindow::closeEvent(QCloseEvent* event) {
  if (tray_ && tray_->isVisible()) {
    hide();
    event->ignore();
    return;
  }
  QMainWindow::closeEvent(event);
}
