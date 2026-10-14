#pragma once
#include <QWidget>
#include <QTabWidget>
#include <QTreeWidget>
#include <QHeaderView>
#include <QStackedWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QFrame>
#include <QMessageBox>
#include <QJsonArray>
#include <QJsonObject>
#include <QDateTime>
#include <QLocale>
#include "DaemonClient.hpp"
#include "Theme.hpp"

class ThreatsPage : public QWidget {
  Q_OBJECT
public:
  ThreatsPage(DaemonClient* client, QWidget* parent = nullptr)
    : QWidget(parent), client_(client) {
    auto* root = new QVBoxLayout(this);

    tabs_ = new QTabWidget;
    tabs_->setDocumentMode(false);
    tabs_->addTab(buildDetectedTab(), Theme::icon({"dialog-warning"}), tr("Detected"));
    tabs_->addTab(buildQuarantineTab(), Theme::icon({"archive-insert", "folder-locked"}), tr("Quarantine"));
    root->addWidget(tabs_, 1);

    connect(client_, &DaemonClient::threatsList, this, &ThreatsPage::fillThreats);
    connect(client_, &DaemonClient::quarantineList, this, &ThreatsPage::fillQuarantine);
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
    v->setRootIsDecorated(false);
    v->setUniformRowHeights(true);
    v->setAlternatingRowColors(true);
    v->setSelectionBehavior(QAbstractItemView::SelectRows);
    v->setSelectionMode(QAbstractItemView::SingleSelection);
    v->setEditTriggers(QAbstractItemView::NoEditTriggers);
    v->header()->setStretchLastSection(false);
    return v;
  }

  // Empty view, drawn like a list view with a centered message.
  static QWidget* placeholder(const QString& text) {
    auto* w = new QFrame;
    w->setFrameShape(QFrame::StyledPanel);
    w->setFrameShadow(QFrame::Sunken);
    w->setBackgroundRole(QPalette::Base);
    w->setAutoFillBackground(true);
    auto* lay = new QVBoxLayout(w);
    lay->addStretch();
    auto* l = Theme::secondaryLabel(text);
    l->setAlignment(Qt::AlignCenter);
    l->setFont(Theme::titleFont(l->font(), 1.1));
    lay->addWidget(l);
    lay->addStretch();
    return w;
  }

  QWidget* buildDetectedTab() {
    auto* w = new QWidget;
    auto* lay = new QVBoxLayout(w);

    threatStack_ = new QStackedWidget;
    threatTable_ = makeView({tr("Severity"), tr("Name"), tr("Path"), tr("Status"), tr("Id")});
    threatTable_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    threatTable_->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    threatTable_->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    threatTable_->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    threatTable_->setColumnHidden(4, true);
    threatStack_->addWidget(placeholder(tr("No active threats")));
    threatStack_->addWidget(threatTable_);
    lay->addWidget(threatStack_, 1);

    auto* row = new QHBoxLayout;
    auto* quar = new QPushButton(Theme::icon({"archive-insert", "edit-move"}), tr("Quarantine"));
    auto* allow = new QPushButton(Theme::icon({"dialog-ok-apply", "dialog-ok"}), tr("Allow"));
    auto* refresh = new QPushButton(Theme::icon({"view-refresh"}), tr("Refresh"));
    quar->setToolTip(tr("Move the selected file to quarantine"));
    allow->setToolTip(tr("Trust the selected file and stop flagging it"));
    quar->setEnabled(false);
    allow->setEnabled(false);
    row->addWidget(quar);
    row->addWidget(allow);
    row->addStretch();
    row->addWidget(refresh);
    lay->addLayout(row);

    connect(threatTable_, &QTreeWidget::itemSelectionChanged, this, [this, quar, allow] {
      const bool sel = threatTable_->currentItem() && threatTable_->currentItem()->isSelected();
      quar->setEnabled(sel);
      allow->setEnabled(sel);
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
    auto* lay = new QVBoxLayout(w);

    quarStack_ = new QStackedWidget;
    quarTable_ = makeView({tr("Threat"), tr("Original Location"), tr("Quarantined"), tr("Id")});
    quarTable_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    quarTable_->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    quarTable_->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    quarTable_->setColumnHidden(3, true);
    quarStack_->addWidget(placeholder(tr("Quarantine is empty")));
    quarStack_->addWidget(quarTable_);
    lay->addWidget(quarStack_, 1);

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
      default: return QObject::tr("Detected");
    }
  }

  void fillThreats(const QJsonArray& arr) {
    threatTable_->clear();
    int shown = 0;
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
                                        o.value("id").toString()});
      item->setIcon(0, Theme::severityIcon(sev));
      item->setToolTip(2, o.value("path").toString());
      threatTable_->addTopLevelItem(item);
      ++shown;
    }
    threatStack_->setCurrentIndex(shown > 0 ? 1 : 0);
  }

  void fillQuarantine(const QJsonArray& arr) {
    quarTable_->clear();
    for (const auto& v : arr) {
      const QJsonObject o = v.toObject();
      const qint64 ts = o.value("quarantinedAt").toVariant().toLongLong();
      auto* item = new QTreeWidgetItem({o.value("threatName").toString(),
                                        o.value("originalPath").toString(),
                                        QLocale().toString(QDateTime::fromSecsSinceEpoch(ts), QLocale::ShortFormat),
                                        o.value("id").toString()});
      item->setToolTip(1, o.value("originalPath").toString());
      quarTable_->addTopLevelItem(item);
    }
    quarStack_->setCurrentIndex(arr.isEmpty() ? 0 : 1);
  }

  DaemonClient* client_;
  QTabWidget* tabs_;
  QStackedWidget* threatStack_;
  QStackedWidget* quarStack_;
  QTreeWidget* threatTable_;
  QTreeWidget* quarTable_;
};
