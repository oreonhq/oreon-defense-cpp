#pragma once
#include <QWidget>
#include <QTabWidget>
#include <QTreeWidget>
#include <QHeaderView>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QJsonArray>
#include <QJsonObject>
#include <QDateTime>
#include <QLocale>
#include <QInputDialog>
#include <QLineEdit>
#include "DaemonClient.hpp"
#include "Theme.hpp"

class ThreatsPage : public QWidget {
  Q_OBJECT
public:
  ThreatsPage(DaemonClient* client, QWidget* parent = nullptr)
    : QWidget(parent), client_(client) {
    auto* root = new QVBoxLayout(this);

    tabs_ = new QTabWidget;
    tabs_->setDocumentMode(true);
    tabs_->addTab(buildDetectedTab(), tr("Detected"));
    tabs_->addTab(buildQuarantineTab(), tr("Quarantine"));
    tabs_->addTab(buildActivityTab(), tr("Log"));
    tabs_->addTab(buildBlockTab(), tr("Blocked Addresses"));
    root->addWidget(tabs_, 1);

    connect(client_, &DaemonClient::threatsList, this, &ThreatsPage::fillThreats);
    connect(client_, &DaemonClient::quarantineList, this, &ThreatsPage::fillQuarantine);
    connect(client_, &DaemonClient::blocklistList, this, &ThreatsPage::fillBlocklist);
    connect(client_, &DaemonClient::threatEvent, this, [this](const QJsonObject&) {
      client_->getThreats();
      client_->getQuarantine();
    });
    connect(client_, &DaemonClient::scanDone, this, [this](const QJsonObject&) {
      client_->getThreats();
      client_->getQuarantine();
    });
  }

private:
  static QTreeWidget* makeView(const QStringList& headers) {
    auto* v = new QTreeWidget;
    v->setHeaderLabels(headers);
    Theme::setupView(v);
    v->header()->setStretchLastSection(false);
    return v;
  }

  QVBoxLayout* tabLayout(QWidget* w) {
    auto* lay = new QVBoxLayout(w);
    lay->setContentsMargins(0, Theme::spacing(this) * 2, 0, 0);
    lay->setSpacing(Theme::spacing(this));
    return lay;
  }

  QWidget* buildDetectedTab() {
    auto* w = new QWidget;
    auto* lay = tabLayout(w);

    threatTable_ = makeView({tr("Severity"), tr("Name"), tr("Path"), tr("Status"), tr("Id"), tr("Pid")});
    threatTable_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    threatTable_->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    threatTable_->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    threatTable_->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    threatTable_->setColumnHidden(4, true);
    threatTable_->setColumnHidden(5, true);
    new Theme::Placeholder(threatTable_, Theme::icon({"security-high", "emblem-ok"}), tr("No threats"));
    lay->addWidget(threatTable_, 1);

    auto* row = new QHBoxLayout;
    auto* quar = new QPushButton(Theme::icon({"archive-insert", "edit-move"}), tr("Quarantine"));
    auto* allow = new QPushButton(Theme::icon({"dialog-ok-apply", "dialog-ok"}), tr("Allow"));
    auto* kill = new QPushButton(Theme::icon({"process-stop", "application-exit"}), tr("Kill Process"));
    auto* refresh = new QPushButton(Theme::icon({"view-refresh"}), tr("Refresh"));
    quar->setToolTip(tr("Move the selected file to quarantine"));
    allow->setToolTip(tr("Trust the selected file and stop flagging it"));
    kill->setToolTip(tr("Stop the selected process"));
    quar->setEnabled(false);
    allow->setEnabled(false);
    kill->setEnabled(false);
    row->addWidget(quar);
    row->addWidget(allow);
    row->addWidget(kill);
    row->addStretch();
    row->addWidget(refresh);
    lay->addLayout(row);

    connect(threatTable_, &QTreeWidget::itemSelectionChanged, this, [this, quar, allow, kill] {
      auto* it = threatTable_->currentItem();
      const bool sel = it && it->isSelected();
      const bool proc = sel && it->text(5).toInt() > 1;
      quar->setEnabled(sel && !proc);
      allow->setEnabled(sel);
      kill->setEnabled(proc);
    });
    connect(kill, &QPushButton::clicked, this, [this] {
      auto* it = threatTable_->currentItem();
      if (!it) return;
      const int pid = it->text(5).toInt();
      if (pid <= 1) return;
      if (QMessageBox::question(this, tr("Kill Process"),
            tr("Stop process %1 (%2)?").arg(pid).arg(it->text(1))) != QMessageBox::Yes)
        return;
      client_->killProcess(pid);
    });
    connect(refresh, &QPushButton::clicked, client_, &DaemonClient::getThreats);
    connect(allow, &QPushButton::clicked, this, [this] {
      auto* it = threatTable_->currentItem();
      if (!it) return;
      client_->allowPath(it->text(2));
    });
    connect(quar, &QPushButton::clicked, this, [this] {
      auto* it = threatTable_->currentItem();
      if (!it) return;
      client_->quarantinePath(it->text(2), it->text(4));
    });
    return w;
  }

  QWidget* buildQuarantineTab() {
    auto* w = new QWidget;
    auto* lay = tabLayout(w);

    quarTable_ = makeView({tr("Threat"), tr("Original Location"), tr("Date"), tr("Id")});
    quarTable_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    quarTable_->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    quarTable_->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    quarTable_->setColumnHidden(3, true);
    new Theme::Placeholder(quarTable_, Theme::icon({"security-high", "emblem-ok"}), tr("Quarantine is empty"));
    lay->addWidget(quarTable_, 1);

    auto* row = new QHBoxLayout;
    auto* restore = new QPushButton(Theme::icon({"document-revert", "edit-undo"}), tr("Restore"));
    auto* del = new QPushButton(Theme::icon({"edit-delete"}), tr("Delete"));
    auto* refresh = new QPushButton(Theme::icon({"view-refresh"}), tr("Refresh"));
    restore->setToolTip(tr("Put the selected file back where it was"));
    del->setToolTip(tr("Delete the selected file permanently"));
    restore->setEnabled(false);
    del->setEnabled(false);
    row->addWidget(restore);
    row->addWidget(del);
    row->addStretch();
    row->addWidget(refresh);
    lay->addLayout(row);

    connect(quarTable_, &QTreeWidget::itemSelectionChanged, this, [this, restore, del] {
      const bool sel = quarTable_->currentItem() && quarTable_->currentItem()->isSelected();
      restore->setEnabled(sel);
      del->setEnabled(sel);
    });
    connect(refresh, &QPushButton::clicked, client_, &DaemonClient::getQuarantine);
    connect(restore, &QPushButton::clicked, this, [this] {
      auto* it = quarTable_->currentItem();
      if (!it) return;
      client_->restore(it->text(3));
    });
    connect(del, &QPushButton::clicked, this, [this] {
      auto* it = quarTable_->currentItem();
      if (!it) return;
      const QString id = it->text(3);
      if (QMessageBox::question(this, tr("Delete File"),
            tr("Delete \"%1\" permanently? This cannot be undone.").arg(it->text(1))) != QMessageBox::Yes)
        return;
      client_->deleteQuarantine(id);
    });
    return w;
  }

  static QString actionLabel(int action) {
    switch (action) {
      case 1: return QObject::tr("Quarantined");
      case 2: return QObject::tr("Allowed");
      case 3: return QObject::tr("Restored");
      case 4: return QObject::tr("Deleted");
      case 5: return QObject::tr("Blocked");
      case 6: return QObject::tr("Process stopped");
      default: return QObject::tr("Detected");
    }
  }

  static QString engineLabel(const QString& e) {
    if (e == QLatin1String("clamav")) return QObject::tr("ClamAV");
    if (e == QLatin1String("rules")) return QObject::tr("Rules");
    if (e == QLatin1String("process")) return QObject::tr("Process");
    return e.isEmpty() ? QObject::tr("Rules") : Theme::capitalized(e);
  }

  QWidget* buildActivityTab() {
    auto* w = new QWidget;
    auto* lay = tabLayout(w);
    actTable_ = makeView({tr("Time"), tr("Severity"), tr("Name"), tr("Path"), tr("Engine"), tr("Action")});
    actTable_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    connect(actTable_, &QTreeWidget::itemActivated, this, [this](QTreeWidgetItem* it, int) {
      if (!it) return;
      const QString details = it->data(0, Qt::UserRole).toString();
      if (details.isEmpty()) return;
      QMessageBox box(this);
      box.setIcon(QMessageBox::Information);
      box.setWindowTitle(tr("Details"));
      box.setText(it->text(2));
      box.setInformativeText(it->text(3));
      box.setDetailedText(details);
      box.setStandardButtons(QMessageBox::Close);
      box.exec();
    });
    actTable_->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    actTable_->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    actTable_->header()->setSectionResizeMode(3, QHeaderView::Stretch);
    actTable_->header()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    actTable_->header()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    actTable_->setSelectionMode(QAbstractItemView::NoSelection);
    new Theme::Placeholder(actTable_, Theme::icon({"view-history", "document-open-recent"}), tr("Nothing found yet"));
    lay->addWidget(actTable_, 1);

    auto* row = new QHBoxLayout;
    auto* refresh = new QPushButton(Theme::icon({"view-refresh"}), tr("Refresh"));
    row->addStretch();
    row->addWidget(refresh);
    lay->addLayout(row);
    connect(refresh, &QPushButton::clicked, client_, &DaemonClient::getThreats);
    return w;
  }

  QWidget* buildBlockTab() {
    auto* w = new QWidget;
    auto* lay = tabLayout(w);
    blockState_ = new QLabel(tr("Network blocking is not active right now."));
    blockState_->setWordWrap(true);
    blockState_->hide();
    lay->addWidget(blockState_);
    blockTable_ = makeView({tr("Address"), tr("Source"), tr("Reason")});
    blockTable_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    blockTable_->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    blockTable_->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    new Theme::Placeholder(blockTable_, Theme::icon({"network-disconnect", "network-wired"}), tr("No blocked addresses"));
    lay->addWidget(blockTable_, 1);

    auto* row = new QHBoxLayout;
    auto* add = new QPushButton(Theme::icon({"list-add"}), tr("Block Address..."));
    auto* remove = new QPushButton(Theme::icon({"list-remove"}), tr("Unblock"));
    auto* refresh = new QPushButton(Theme::icon({"view-refresh"}), tr("Refresh"));
    remove->setEnabled(false);
    row->addWidget(add);
    row->addWidget(remove);
    row->addStretch();
    row->addWidget(refresh);
    lay->addLayout(row);

    connect(blockTable_, &QTreeWidget::itemSelectionChanged, this, [this, remove] {
      remove->setEnabled(blockTable_->currentItem() && blockTable_->currentItem()->isSelected());
    });
    connect(refresh, &QPushButton::clicked, client_, &DaemonClient::getBlocklist);
    connect(add, &QPushButton::clicked, this, [this] {
      bool ok = false;
      const QString ip = QInputDialog::getText(this, tr("Block Address"),
        tr("IP address or range, for example 203.0.113.7 or 198.51.100.0/24:"),
        QLineEdit::Normal, QString(), &ok).trimmed();
      if (ok && !ip.isEmpty()) client_->blockIp(ip, tr("Blocked by user"));
    });
    connect(remove, &QPushButton::clicked, this, [this] {
      auto* it = blockTable_->currentItem();
      if (it) client_->unblockIp(it->text(0));
    });
    return w;
  }

  void fillBlocklist(const QJsonArray& arr, bool active) {
    blockTable_->clear();
    for (const auto& v : arr) {
      const QJsonObject o = v.toObject();
      const QString src = o.value("source").toString();
      auto* item = new QTreeWidgetItem({o.value("cidr").toString(),
                                        src == QLatin1String("feed") ? tr("Rule feed") : tr("You"),
                                        o.value("reason").toString()});
      blockTable_->addTopLevelItem(item);
    }
    blockState_->setVisible(!active);
  }

  void fillThreats(const QJsonArray& arr) {
    threatTable_->clear();
    actTable_->clear();
    for (int i = arr.size() - 1; i >= 0; --i) {
      const QJsonObject o = arr.at(i).toObject();
      const QString sev = o.value("severity").toString();
      const qint64 ts = o.value("timestamp").toVariant().toLongLong();
      auto* item = new QTreeWidgetItem({
        Theme::when(ts),
        Theme::capitalized(sev), o.value("name").toString(), o.value("path").toString(),
        engineLabel(o.value("engine").toString()), actionLabel(o.value("action").toInt(0))});
      item->setIcon(1, Theme::severityIcon(sev));
      item->setToolTip(3, o.value("description").toString());
      item->setData(0, Qt::UserRole, o.value("description").toString());
      actTable_->addTopLevelItem(item);
    }
    for (const auto& v : arr) {
      const QJsonObject o = v.toObject();
      const int action = o.value("action").toInt(0);
      // Detected tab: show Detected / Blocked only
      if (action != 0 && action != 5) continue;
      const QString sev = o.value("severity").toString();
      auto* item = new QTreeWidgetItem({Theme::capitalized(sev),
                                        o.value("name").toString(),
                                        o.value("path").toString(),
                                        actionLabel(action),
                                        o.value("id").toString(),
                                        QString::number(o.value("kind").toString() == QLatin1String("process")
                                                          ? o.value("pid").toInt() : 0)});
      item->setIcon(0, Theme::severityIcon(sev));
      item->setToolTip(2, o.value("path").toString());
      threatTable_->addTopLevelItem(item);
    }
  }

  void fillQuarantine(const QJsonArray& arr) {
    quarTable_->clear();
    for (const auto& v : arr) {
      const QJsonObject o = v.toObject();
      const qint64 ts = o.value("quarantinedAt").toVariant().toLongLong();
      auto* item = new QTreeWidgetItem({o.value("threatName").toString(),
                                        o.value("originalPath").toString(),
                                        Theme::when(ts),
                                        o.value("id").toString()});
      item->setToolTip(1, o.value("originalPath").toString());
      quarTable_->addTopLevelItem(item);
    }
  }

  DaemonClient* client_;
  QTabWidget* tabs_;
  QTreeWidget* threatTable_;
  QTreeWidget* quarTable_;
  QTreeWidget* actTable_{nullptr};
  QTreeWidget* blockTable_{nullptr};
  QLabel* blockState_{nullptr};
};
