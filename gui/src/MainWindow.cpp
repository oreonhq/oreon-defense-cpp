#include "MainWindow.hpp"
#include "pages/HomePage.hpp"
#include "pages/ScansPage.hpp"
#include "pages/ThreatsPage.hpp"
#include "pages/HistoryPage.hpp"
#include "pages/SettingsPage.hpp"
#include "Theme.hpp"
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QFrame>
#include <QDBusInterface>
#include <QMessageBox>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
  client_ = new DaemonClient(this);
  setupUi();
  setupTray();
  setWindowTitle(tr("Oreon Defense"));
  setWindowIcon(QIcon::fromTheme("oreon-defense", Theme::icon({"security-high"})));
  resize(960, 680);
  // offline until first successful connect
  emit client_->connectedChanged(false);
  if (tray_) tray_->setProtected(false);
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
    {tr("Threats"), {"dialog-warning", "security-medium"}},
    {tr("History"), {"view-history", "document-open-recent"}},
    {tr("Settings"), {"configure", "preferences-system"}},
  };
  for (const auto& it : items) {
    auto* item = new QListWidgetItem(Theme::icon(it.icons), it.text);
    item->setSizeHint(QSize(0, nav_->iconSize().height() + 2 * Theme::spacing(nav_) + 4));
    nav_->addItem(item);
  }
  int navWidth = 0;
  for (const auto& it : items)
    navWidth = qMax(navWidth, nav_->fontMetrics().horizontalAdvance(it.text));
  nav_->setFixedWidth(qMax(180, navWidth + nav_->iconSize().width() + 48));

  // Sidebar sits on the view background with a little breathing room.
  auto* side = new QWidget;
  side->setBackgroundRole(QPalette::Base);
  side->setAutoFillBackground(true);
  auto* sideLay = new QVBoxLayout(side);
  const int sm = Theme::spacing(nav_);
  sideLay->setContentsMargins(sm, sm, sm, sm);
  sideLay->addWidget(nav_);

  auto* sep = new QFrame;
  sep->setFrameShape(QFrame::VLine);
  sep->setFrameShadow(QFrame::Sunken);

  // Right side: page title like System Settings, then the page.
  auto* right = new QWidget;
  auto* rightLay = new QVBoxLayout(right);
  rightLay->setContentsMargins(0, 0, 0, 0);
  rightLay->setSpacing(0);
  pageTitle_ = Theme::heading(items.first().text, 1.2);
  const int m = Theme::margin(this);
  pageTitle_->setContentsMargins(m * 2, m + 2, m * 2, m + 2);
  auto* hsep = new QFrame;
  hsep->setFrameShape(QFrame::HLine);
  hsep->setFrameShadow(QFrame::Sunken);

  stack_ = new QStackedWidget;
  stack_->addWidget(new HomePage(client_));
  stack_->addWidget(new ScansPage(client_));
  stack_->addWidget(new ThreatsPage(client_));
  stack_->addWidget(new HistoryPage(client_));
  settings_ = new SettingsPage(client_);
  stack_->addWidget(settings_);
  for (int i = 0; i < stack_->count(); ++i) {
    if (auto* l = stack_->widget(i)->layout())
      l->setContentsMargins(m * 2, m * 2, m * 2, m * 2);
  }

  rightLay->addWidget(pageTitle_);
  rightLay->addWidget(hsep);
  rightLay->addWidget(stack_, 1);

  lay->addWidget(side);
  lay->addWidget(sep);
  lay->addWidget(right, 1);
  setCentralWidget(central);
  nav_->setCurrentRow(0);

  connect(nav_, &QListWidget::currentRowChanged, this, [this](int row) {
    if (auto* it = nav_->item(row)) pageTitle_->setText(it->text());
  });
  connect(nav_, &QListWidget::currentRowChanged, stack_, &QStackedWidget::setCurrentIndex);
  connect(client_, &DaemonClient::connectedChanged, this, [this](bool ok) {
    if (tray_) tray_->setProtected(ok);
  });
  connect(client_, &DaemonClient::statusUpdated, this, [this](const QJsonObject& s) {
    const bool ok = s.value("protected").toBool(true);
    if (tray_) tray_->setProtected(ok && client_->isConnected());
  });
  connect(client_, &DaemonClient::threatEvent, this, &MainWindow::notifyThreat);
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

void MainWindow::notifyThreat(const QJsonObject& threat) {
  if (!notifications_) return;
  const QString title = tr("Oreon Defense");
  const QString body = tr("Threat: %1\n%2")
    .arg(threat.value("name").toString(), threat.value("path").toString());
  if (tray_)
    tray_->showMessage(title, body, QSystemTrayIcon::Warning, 6000);
  QDBusInterface iface("org.freedesktop.Notifications",
                       "/org/freedesktop/Notifications",
                       "org.freedesktop.Notifications");
  if (iface.isValid()) {
    iface.call("Notify", "Oreon Defense", uint(0), "security-low",
               title, body, QStringList(), QVariantMap(), 6000);
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
