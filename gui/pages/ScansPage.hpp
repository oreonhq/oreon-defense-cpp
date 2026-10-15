#pragma once
#include <QWidget>
#include <QPushButton>
#include <QRadioButton>
#include <QButtonGroup>
#include <QProgressBar>
#include <QLabel>
#include <QLineEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QTreeWidget>
#include <QHeaderView>
#include <QJsonObject>
#include <QLocale>
#include "DaemonClient.hpp"
#include "Theme.hpp"
#include "ScanText.hpp"

class ScansPage : public QWidget {
  Q_OBJECT
public:
  ScansPage(DaemonClient* client, QWidget* parent = nullptr)
    : QWidget(parent), client_(client) {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(Theme::spacing(this));

    auto* typeLay = new QVBoxLayout;
    typeLay->setSpacing(Theme::spacing(this));
    quick_ = new QRadioButton(tr("Quick scan"));
    quick_->setToolTip(tr("Common places like Downloads and Desktop"));
    full_ = new QRadioButton(tr("Full scan"));
    full_->setToolTip(tr("The whole system"));
    custom_ = new QRadioButton(tr("Folder:"));
    quick_->setChecked(true);
    auto* group = new QButtonGroup(this);
    group->addButton(quick_);
    group->addButton(full_);
    group->addButton(custom_);
    typeLay->addWidget(quick_);
    typeLay->addWidget(full_);
    auto* pathRow = new QHBoxLayout;
    pathRow->setSpacing(Theme::spacing(this));
    path_ = new QLineEdit;
    path_->setMaximumWidth(path_->fontMetrics().averageCharWidth() * 50);
    path_->setPlaceholderText(tr("Choose a folder"));
    path_->setClearButtonEnabled(true);
    browse_ = new QPushButton(Theme::icon({"document-open-folder", "folder-open"}), tr("Browse..."));
    pathRow->addWidget(custom_);
    pathRow->addWidget(path_, 1);
    pathRow->addWidget(browse_);
    pathRow->addStretch(1);
    typeLay->addLayout(pathRow);
    root->addLayout(typeLay);
    Theme::addSectionGap(root, this);

    auto* startRow = new QHBoxLayout;
    startRow->setSpacing(Theme::spacing(this));
    start_ = new QPushButton(Theme::icon({"system-search", "edit-find"}), tr("Start Scan"));
    startRow->addWidget(start_);
    startRow->addStretch(1);
    root->addLayout(startRow);
    Theme::addSectionGap(root, this);

    results_ = new QWidget;
    auto* resLay = new QVBoxLayout(results_);
    resLay->setContentsMargins(0, 0, 0, 0);
    resLay->setSpacing(Theme::spacing(this));
    progressRow_ = new QWidget;
    auto* barRow = new QHBoxLayout(progressRow_);
    barRow->setContentsMargins(0, 0, 0, 0);
    barRow->setSpacing(Theme::spacing(this));
    progress_ = new QProgressBar;
    progress_->setRange(0, 100);
    progress_->setTextVisible(true);
    cancel_ = new QPushButton(Theme::icon({"dialog-cancel", "process-stop"}), tr("Cancel"));
    cancel_->setEnabled(false);
    barRow->addWidget(progress_, 1);
    barRow->addWidget(cancel_);
    resLay->addWidget(progressRow_);
    status_ = new QLabel;
    resLay->addWidget(status_);
    found_ = new QTreeWidget;
    found_->setHeaderLabels({tr("Severity"), tr("Name"), tr("Path")});
    Theme::setupView(found_);
    found_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    found_->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    found_->header()->setStretchLastSection(true);
    new Theme::Placeholder(found_, Theme::icon({"security-high", "emblem-ok"}), tr("No threats found"));
    resLay->addWidget(found_, 1);
    root->addWidget(results_, 1);
    results_->hide();
    root->addStretch(0);

    auto updateCustom = [this] {
      path_->setEnabled(custom_->isChecked());
      browse_->setEnabled(custom_->isChecked());
    };
    connect(custom_, &QRadioButton::toggled, this, updateCustom);
    updateCustom();

    connect(browse_, &QPushButton::clicked, this, [this] {
      const QString dir = QFileDialog::getExistingDirectory(this, tr("Select Folder"), path_->text());
      if (!dir.isEmpty()) path_->setText(dir);
    });
    connect(start_, &QPushButton::clicked, this, &ScansPage::startScan);
    connect(path_, &QLineEdit::returnPressed, this, &ScansPage::startScan);
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
      found_->addTopLevelItem(item);
      if (scanActive_) ++scanHits_;
    });
  }

private:
  static QString threatsText(int n) { return ScanText::threats(n); }

  int listed() const { return scanHits_; }

  void showResults() {
    results_->setVisible(true);
  }

  void startScan() {
    scanHits_ = 0;
    scanActive_ = true;
    if (custom_->isChecked()) {
      const QString p = path_->text().trimmed();
      if (p.isEmpty()) {
        path_->setFocus();
        return;
      }
      found_->clear();
      client_->startScan("custom", {p});
    } else {
      found_->clear();
      client_->startScan(full_->isChecked() ? "full" : "quick");
    }
  }

  void onProgress(const QJsonObject& p) {
    showResults();
    const bool running = p.value("running").toBool();
    cancel_->setEnabled(running);
    start_->setEnabled(!running);
    progressRow_->setVisible(running);
    const qint64 total = p.value("filesTotal").toVariant().toLongLong();
    const qint64 done = p.value("filesScanned").toVariant().toLongLong();
    if (total > 0) {
      progress_->setRange(0, 100);
      progress_->setValue(int((done * 100) / total));
    } else {
      progress_->setRange(0, 0);
    }
    const QLocale loc;
    const int threats = ScanText::detectionCount(p.value("threatsFound").toVariant().toLongLong(), listed());
    const QString files = total > 0
      ? tr("%1 of %2 files checked").arg(loc.toString(done), loc.toString(total))
      : tr("%1 files checked").arg(loc.toString(done));
    status_->setText(files + QStringLiteral(", ") + threatsText(threats));
  }

  void onDone(const QJsonObject& p) {
    showResults();
    progress_->setRange(0, 100);
    progress_->setValue(100);
    cancel_->setEnabled(false);
    start_->setEnabled(true);
    progressRow_->hide();
    const int threats = ScanText::detectionCount(p.value("threatsFound").toVariant().toLongLong(), listed());
    scanActive_ = false;
    status_->setText(ScanText::finished(p.value("cancelled").toBool(), threats));
    client_->getThreats();
    client_->getQuarantine();
  }

  DaemonClient* client_;
  QRadioButton* quick_;
  QRadioButton* full_;
  QRadioButton* custom_;
  QLineEdit* path_;
  QPushButton* browse_;
  QPushButton* start_;
  QWidget* results_;
  QWidget* progressRow_;
  QProgressBar* progress_;
  QLabel* status_;
  QPushButton* cancel_;
  QTreeWidget* found_;
  int scanHits_{0};
  bool scanActive_{false};
};
