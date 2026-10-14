#pragma once
#include <QWidget>
#include <QPushButton>
#include <QProgressBar>
#include <QLabel>
#include <QLineEdit>
#include <QGroupBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QTreeWidget>
#include <QHeaderView>
#include <QJsonObject>
#include "DaemonClient.hpp"
#include "Theme.hpp"

class ScansPage : public QWidget {
  Q_OBJECT
public:
  ScansPage(DaemonClient* client, QWidget* parent = nullptr)
    : QWidget(parent), client_(client) {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(Theme::spacing(this) * 2);

    // Scan type
    auto* runBox = new QGroupBox(tr("Run a Scan"));
    auto* runLay = new QVBoxLayout(runBox);
    auto* btnRow = new QHBoxLayout;
    auto* quick = new QPushButton(Theme::icon({"system-search", "edit-find"}), tr("Quick Scan"));
    auto* full = new QPushButton(Theme::icon({"view-refresh"}), tr("Full Scan"));
    quick->setToolTip(tr("Scan common places like Downloads and Desktop"));
    full->setToolTip(tr("Scan the whole system"));
    btnRow->addWidget(quick);
    btnRow->addWidget(full);
    btnRow->addStretch();
    runLay->addLayout(btnRow);

    auto* pathRow = new QHBoxLayout;
    path_ = new QLineEdit;
    path_->setPlaceholderText(tr("Choose a folder to scan"));
    path_->setClearButtonEnabled(true);
    auto* browse = new QPushButton(Theme::icon({"document-open-folder", "folder-open"}), tr("Browse..."));
    auto* custom = new QPushButton(Theme::icon({"folder-search", "system-search"}), tr("Scan Folder"));
    pathRow->addWidget(new QLabel(tr("Folder:")));
    pathRow->addWidget(path_, 1);
    pathRow->addWidget(browse);
    pathRow->addWidget(custom);
    runLay->addLayout(pathRow);
    root->addWidget(runBox);

    // Progress
    auto* progBox = new QGroupBox(tr("Progress"));
    auto* progLay = new QVBoxLayout(progBox);
    auto* barRow = new QHBoxLayout;
    progress_ = new QProgressBar;
    progress_->setRange(0, 100);
    progress_->setValue(0);
    progress_->setTextVisible(true);
    cancel_ = new QPushButton(Theme::icon({"dialog-cancel", "process-stop"}), tr("Cancel"));
    cancel_->setEnabled(false);
    barRow->addWidget(progress_, 1);
    barRow->addWidget(cancel_);
    progLay->addLayout(barRow);
    status_ = Theme::secondaryLabel(tr("No scan running."));
    progLay->addWidget(status_);
    root->addWidget(progBox);

    // Findings
    auto* resBox = new QGroupBox(tr("Findings"));
    auto* resLay = new QVBoxLayout(resBox);
    results_ = new QTreeWidget;
    results_->setHeaderLabels({tr("Severity"), tr("Name"), tr("Path")});
    results_->setRootIsDecorated(false);
    results_->setUniformRowHeights(true);
    results_->setAlternatingRowColors(true);
    results_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    results_->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    results_->header()->setStretchLastSection(true);
    resLay->addWidget(results_);
    root->addWidget(resBox, 1);

    connect(browse, &QPushButton::clicked, this, [this] {
      const QString dir = QFileDialog::getExistingDirectory(this, tr("Select Folder"));
      if (!dir.isEmpty()) path_->setText(dir);
    });
    connect(quick, &QPushButton::clicked, this, [this] {
      results_->clear();
      client_->startScan("quick");
    });
    connect(full, &QPushButton::clicked, this, [this] {
      results_->clear();
      client_->startScan("full");
    });
    connect(custom, &QPushButton::clicked, this, [this] {
      results_->clear();
      const QString p = path_->text().trimmed();
      if (p.isEmpty()) {
        status_->setText(tr("Choose a folder first."));
        return;
      }
      client_->startScan("custom", {p});
    });
    connect(cancel_, &QPushButton::clicked, client_, &DaemonClient::cancelScan);
    connect(client_, &DaemonClient::scanProgress, this, &ScansPage::onProgress);
    connect(client_, &DaemonClient::scanDone, this, &ScansPage::onDone);
    connect(client_, &DaemonClient::threatEvent, this, [this](const QJsonObject& t) {
      const QString sev = t.value("severity").toString();
      auto* item = new QTreeWidgetItem({Theme::capitalized(sev),
                                        t.value("name").toString(),
                                        t.value("path").toString()});
      item->setIcon(0, Theme::severityIcon(sev));
      item->setToolTip(2, t.value("path").toString());
      results_->addTopLevelItem(item);
    });
  }

private:
  void onProgress(const QJsonObject& p) {
    cancel_->setEnabled(p.value("running").toBool());
    const qint64 total = p.value("filesTotal").toVariant().toLongLong();
    const qint64 done = p.value("filesScanned").toVariant().toLongLong();
    if (total > 0) {
      progress_->setRange(0, 100);
      progress_->setValue(int((done * 100) / total));
    } else {
      progress_->setRange(0, 0);
    }
    status_->setText(tr("Scanned %1 of %2 files. Threats found: %3")
      .arg(done).arg(total).arg(p.value("threatsFound").toVariant().toLongLong()));
  }

  void onDone(const QJsonObject& p) {
    progress_->setRange(0, 100);
    progress_->setValue(100);
    cancel_->setEnabled(false);
    if (p.value("cancelled").toBool())
      status_->setText(tr("Scan cancelled."));
    else
      status_->setText(tr("Scan finished. Threats found: %1")
        .arg(p.value("threatsFound").toVariant().toLongLong()));
    client_->getThreats();
    client_->getQuarantine();
  }

  DaemonClient* client_;
  QLineEdit* path_;
  QProgressBar* progress_;
  QLabel* status_;
  QPushButton* cancel_;
  QTreeWidget* results_;
};
