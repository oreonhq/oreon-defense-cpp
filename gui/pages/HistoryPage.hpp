#pragma once
#include <QWidget>
#include <QTabWidget>
#include <QTreeWidget>
#include <QHeaderView>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTimer>
#include <QDateTime>
#include <QLocale>
#include <QJsonArray>
#include <QJsonObject>
#include "DaemonClient.hpp"
#include "Theme.hpp"

class HistoryPage : public QWidget {
  Q_OBJECT
public:
  HistoryPage(DaemonClient* client, QWidget* parent = nullptr)
    : QWidget(parent), client_(client) {
    auto* root = new QVBoxLayout(this);
    auto* tabs = new QTabWidget;
    tabs->setDocumentMode(true);
    tabs->addTab(buildEventsTab(), tr("Events"));
    tabs->addTab(buildNetworkTab(), tr("Network"));
    root->addWidget(tabs, 1);

    connect(client_, &DaemonClient::historyList, this, &HistoryPage::fillHistory);
    connect(client_, &DaemonClient::networkList, this, &HistoryPage::fillNetwork);

    auto* timer = new QTimer(this);
    connect(timer, &QTimer::timeout, client_, &DaemonClient::getNetwork);
    timer->start(8000);
  }

private:
  QVBoxLayout* tabLayout(QWidget* w) {
    auto* lay = new QVBoxLayout(w);
    lay->setContentsMargins(0, Theme::spacing(this) * 2, 0, 0);
    lay->setSpacing(Theme::spacing(this));
    return lay;
  }

  QWidget* buildEventsTab() {
    auto* w = new QWidget;
    auto* lay = tabLayout(w);
    search_ = new QLineEdit;
    search_->setPlaceholderText(tr("Search"));
    search_->setClearButtonEnabled(true);
    search_->addAction(Theme::icon({"search", "edit-find"}), QLineEdit::LeadingPosition);
    lay->addWidget(search_);

    history_ = new QTreeWidget;
    history_->setHeaderLabels({tr("Time"), tr("Type"), tr("Details")});
    Theme::setupView(history_);
    history_->setTextElideMode(Qt::ElideRight);
    history_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    history_->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    history_->header()->setStretchLastSection(true);
    placeholder_ = new Theme::Placeholder(history_, Theme::icon({"view-history", "document-open-recent"}),
                                          tr("No events"));
    lay->addWidget(history_, 1);

    auto* debounce = new QTimer(this);
    debounce->setSingleShot(true);
    debounce->setInterval(300);
    connect(search_, &QLineEdit::textChanged, debounce, qOverload<>(&QTimer::start));
    connect(search_, &QLineEdit::returnPressed, debounce, qOverload<>(&QTimer::start));
    connect(debounce, &QTimer::timeout, this, [this] { client_->getHistory(search_->text()); });
    connect(client_, &DaemonClient::logEvent, debounce, qOverload<>(&QTimer::start));
    return w;
  }

  QWidget* buildNetworkTab() {
    auto* w = new QWidget;
    auto* lay = tabLayout(w);
    net_ = new QTreeWidget;
    net_->setHeaderLabels({tr("Process"), tr("Local Address"), tr("Remote Address"), tr("State"), tr("Risk"), tr("Ip")});
    Theme::setupView(net_);
    net_->header()->setStretchLastSection(false);
    for (int c = 0; c < 5; ++c)
      net_->header()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
    net_->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    net_->setColumnHidden(5, true);
    new Theme::Placeholder(net_, Theme::icon({"network-wired", "network-connect"}), tr("No connections"));
    lay->addWidget(net_, 1);

    auto* row = new QHBoxLayout;
    auto* block = new QPushButton(Theme::icon({"network-disconnect", "dialog-cancel"}), tr("Block Remote Address"));
    block->setToolTip(tr("Block all traffic to and from the selected remote address"));
    block->setEnabled(false);
    row->addWidget(block);
    row->addStretch();
    lay->addLayout(row);
    connect(net_, &QTreeWidget::itemSelectionChanged, this, [this, block] {
      auto* it = net_->currentItem();
      block->setEnabled(it && it->isSelected() && !it->text(5).isEmpty());
    });
    connect(block, &QPushButton::clicked, this, [this] {
      auto* it = net_->currentItem();
      if (!it || it->text(5).isEmpty()) return;
      client_->blockIp(it->text(5), tr("Blocked from connections list (%1)").arg(it->text(0)));
    });
    return w;
  }

  void fillHistory(const QJsonArray& arr) {
    history_->clear();
    placeholder_->setText(search_->text().trimmed().isEmpty() ? tr("No events") : tr("No matching events"));
    for (const auto& v : arr) {
      const QJsonObject o = v.toObject();
      const qint64 ts = o.value("timestamp").toVariant().toLongLong();
      const QString cat = o.value("category").toString();
      auto* item = new QTreeWidgetItem({Theme::when(ts), Theme::capitalized(cat),
                                        o.value("message").toString()});
      item->setToolTip(2, o.value("message").toString());
      history_->addTopLevelItem(item);
      if (history_->topLevelItemCount() >= 50) break;
    }
  }

  void fillNetwork(const QJsonArray& arr) {
    QString selKey;
    if (auto* cur = net_->currentItem(); cur && cur->isSelected())
      selKey = cur->text(0) + cur->text(1) + cur->text(2);
    net_->clear();
    int n = 0;
    for (const auto& v : arr) {
      const QJsonObject o = v.toObject();
      const QString state = o.value("state").toString();
      const bool listen = state == QLatin1String("LISTEN");
      const QString risk = o.value("risk").toString();
      const QString ip = listen ? QString() : o.value("remoteIp").toString();
      auto* item = new QTreeWidgetItem({
        QStringLiteral("%1 (%2)").arg(o.value("process").toString()).arg(o.value("pid").toInt()),
        o.value("localAddr").toString(),
        listen ? QString() : o.value("remoteAddr").toString(),
        listen ? tr("Listening") : tr("Connected"),
        risk == QLatin1String("ok") ? QString() : Theme::capitalized(risk),
        ip});
      if (risk == QLatin1String("high") || risk == QLatin1String("blocked"))
        item->setIcon(4, Theme::icon({"dialog-error"}));
      else if (risk == QLatin1String("watch"))
        item->setIcon(4, Theme::icon({"dialog-warning"}));
      net_->addTopLevelItem(item);
      if (!selKey.isEmpty() && selKey == item->text(0) + item->text(1) + item->text(2)) {
        net_->setCurrentItem(item);
      }
      if (++n >= 100) break;
    }
  }

  DaemonClient* client_;
  QLineEdit* search_;
  QTreeWidget* history_;
  Theme::Placeholder* placeholder_;
  QTreeWidget* net_;
};
