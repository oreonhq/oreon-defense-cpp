#pragma once
#include <QWidget>
#include <QGroupBox>
#include <QTreeWidget>
#include <QHeaderView>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QTimer>
#include <QDateTime>
#include <QLocale>
#include <QJsonArray>
#include <QJsonObject>
#include "DaemonClient.hpp"
#include "Theme.hpp"

// Event history search and the current listening ports.
class HistoryPage : public QWidget {
  Q_OBJECT
public:
  HistoryPage(DaemonClient* client, QWidget* parent = nullptr)
    : QWidget(parent), client_(client) {
    auto* root = new QVBoxLayout(this);

    auto* split = new QSplitter(Qt::Vertical);
    split->setChildrenCollapsible(false);

    // History
    auto* histBox = new QGroupBox(tr("Event History"));
    auto* histLay = new QVBoxLayout(histBox);
    auto* searchRow = new QHBoxLayout;
    search_ = new QLineEdit;
    search_->setPlaceholderText(tr("Search events"));
    search_->setClearButtonEnabled(true);
    auto* go = new QPushButton(Theme::icon({"system-search", "edit-find"}), tr("Search"));
    searchRow->addWidget(search_, 1);
    searchRow->addWidget(go);
    histLay->addLayout(searchRow);
    history_ = new QTreeWidget;
    history_->setHeaderLabels({tr("Time"), tr("Type"), tr("Details")});
    history_->setRootIsDecorated(false);
    history_->setUniformRowHeights(true);
    history_->setAlternatingRowColors(true);
    history_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    history_->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    history_->header()->setStretchLastSection(true);
    histLay->addWidget(history_, 1);
    split->addWidget(histBox);

    // Network listeners
    auto* netBox = new QGroupBox(tr("Listening Ports"));
    auto* netLay = new QVBoxLayout(netBox);
    net_ = new QTreeWidget;
    net_->setHeaderLabels({tr("Risk"), tr("Local Address"), tr("Process")});
    net_->setRootIsDecorated(false);
    net_->setUniformRowHeights(true);
    net_->setAlternatingRowColors(true);
    net_->setSelectionMode(QAbstractItemView::NoSelection);
    net_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    net_->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    net_->header()->setStretchLastSection(true);
    netLay->addWidget(net_, 1);
    split->addWidget(netBox);
    split->setStretchFactor(0, 3);
    split->setStretchFactor(1, 2);
    root->addWidget(split, 1);

    auto doSearch = [this] { client_->getHistory(search_->text()); };
    connect(go, &QPushButton::clicked, this, doSearch);
    connect(search_, &QLineEdit::returnPressed, this, doSearch);
    connect(client_, &DaemonClient::historyList, this, &HistoryPage::fillHistory);
    connect(client_, &DaemonClient::networkList, this, &HistoryPage::fillNetwork);

    auto* timer = new QTimer(this);
    connect(timer, &QTimer::timeout, client_, &DaemonClient::getNetwork);
    timer->start(8000);
  }

private:
  void fillHistory(const QJsonArray& arr) {
    history_->clear();
    for (const auto& v : arr) {
      const QJsonObject o = v.toObject();
      const qint64 ts = o.value("timestamp").toVariant().toLongLong();
      const QString cat = o.value("category").toString();
      auto* item = new QTreeWidgetItem({
        QLocale().toString(QDateTime::fromSecsSinceEpoch(ts), QLocale::ShortFormat),
        Theme::capitalized(cat),
        o.value("message").toString()});
      if (cat == QLatin1String("threat"))
        item->setIcon(1, Theme::icon({"dialog-warning"}));
      item->setToolTip(2, o.value("message").toString());
      history_->addTopLevelItem(item);
      if (history_->topLevelItemCount() >= 50) break;
    }
  }

  void fillNetwork(const QJsonArray& arr) {
    net_->clear();
    int n = 0;
    for (const auto& v : arr) {
      const QJsonObject o = v.toObject();
      if (o.value("state").toString() != "LISTEN") continue;
      const QString risk = o.value("risk").toString();
      auto* item = new QTreeWidgetItem({
        risk == QLatin1String("ok") ? tr("OK") : Theme::capitalized(risk),
        o.value("localAddr").toString(),
        QString("%1 (%2)").arg(o.value("process").toString()).arg(o.value("pid").toInt())});
      if (risk == QLatin1String("high"))
        item->setIcon(0, Theme::icon({"dialog-error"}));
      else if (risk == QLatin1String("watch"))
        item->setIcon(0, Theme::icon({"dialog-warning"}));
      net_->addTopLevelItem(item);
      if (++n >= 12) break;
    }
  }

  DaemonClient* client_;
  QLineEdit* search_;
  QTreeWidget* history_;
  QTreeWidget* net_;
};
