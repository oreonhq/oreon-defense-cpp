#pragma once
#include <QWidget>
#include <QTimeEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QCheckBox>
#include <QListWidget>
#include <QStackedWidget>
#include <QScrollArea>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFrame>
#include <QJsonObject>
#include <QJsonArray>
#include <QTime>
#include <QDateTime>
#include <QLocale>
#include "DaemonClient.hpp"
#include "Theme.hpp"

class SettingsPage : public QWidget {
  Q_OBJECT
public:
  SettingsPage(DaemonClient* client, QWidget* parent = nullptr)
    : QWidget(parent), client_(client) {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(Theme::spacing(this) * 2);

    auto* split = new QHBoxLayout;
    split->setSpacing(0);

    cats_ = new QListWidget;
    cats_->setObjectName(QStringLiteral("settingsCategories"));
    cats_->setFrameShape(QFrame::NoFrame);
    cats_->setIconSize(QSize(22, 22));
    cats_->setUniformItemSizes(true);
    cats_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    cats_->setSpacing(1);
    cats_->setBackgroundRole(QPalette::Base);
    cats_->setAutoFillBackground(true);

    stack_ = new QStackedWidget;

    auto check = [this](const QString& text, const QString& tip = {}) {
      auto* c = new QCheckBox(text);
      c->setChecked(true);
      if (!tip.isEmpty()) c->setToolTip(tip);
      connect(c, &QCheckBox::toggled, this, &SettingsPage::updateButtons);
      return c;
    };

    {
      auto* form = beginCategory(tr("Protection"), {"security-high", "preferences-system"});
      fileRt_ = check(tr("Check new and changed files"));
      onAccess_ = check(tr("Block threats before files open or run"),
                        tr("Uses fanotify. Falls back to checking new files when the kernel does not allow it."));
      form->addRow(tr("Files:"), fileRt_);
      form->addRow(QString(), onAccess_);
      maxMb_ = new QSpinBox;
      maxMb_->setRange(1, 4096);
      maxMb_->setSuffix(tr(" MB"));
      maxMb_->setValue(200);
      maxMb_->setToolTip(tr("Files larger than this are skipped during the quick real-time check."));
      connect(maxMb_, &QSpinBox::valueChanged, this, &SettingsPage::updateButtons);
      form->addRow(tr("Largest file to check live:"), maxMb_);
    }

    {
      auto* form = beginCategory(tr("Processes"), {"system-run", "application-x-executable"});
      proc_ = check(tr("Watch new processes"));
      kill_ = check(tr("Stop malicious processes"),
                    tr("End processes that match a rule or a virus signature"));
      form->addRow(tr("Processes:"), proc_);
      form->addRow(QString(), kill_);
    }

    {
      auto* form = beginCategory(tr("Network"), {"network-wired", "network-workgroup"});
      net_ = check(tr("Watch connections and listening ports"));
      netBlock_ = check(tr("Block known bad addresses"),
                        tr("Uses an nftables table with the addresses from the rule feed and your own list"));
      form->addRow(tr("Network:"), net_);
      form->addRow(QString(), netBlock_);
    }

    {
      auto* form = beginCategory(tr("Advanced Defense"), {"security-medium", "dialog-password"});
      ransom_ = check(tr("Protect my files from ransomware"),
                      tr("Places hidden canary files and watches for a program that rewrites many files quickly."));
      exec_ = check(tr("Block unknown programs in downloads and temp folders"),
                    tr("Programs that are not from a package are blocked in /tmp and /dev/shm and flagged in Downloads."));
      persist_ = check(tr("Watch startup and login files"),
                       tr("Alerts when autostart, cron, shell startup files or SSH keys change outside an update."));
      revshell_ = check(tr("Detect reverse shells and remote control"),
                        tr("Stops shells wired to a network socket and common remote-control patterns."));
      privesc_ = check(tr("Watch for privilege escalation"),
                       tr("Alerts on new setuid programs and changes to account and sudo files."));
      form->addRow(tr("Ransomware shield:"), ransom_);
      form->addRow(tr("Download protection:"), exec_);
      form->addRow(tr("Persistence guard:"), persist_);
      form->addRow(tr("Reverse shells:"), revshell_);
      form->addRow(tr("Privilege watch:"), privesc_);
    }

    {
      auto* form = beginCategory(tr("Updates"), {"system-software-update", "view-refresh"});
      clam_ = check(tr("Use ClamAV virus signatures"));
      autoUpd_ = check(tr("Update rules automatically"));
      form->addRow(tr("Signatures:"), clam_);
      form->addRow(tr("Rules:"), autoUpd_);
      auto* rulesRow = new QHBoxLayout;
      auto* updateNow = new QPushButton(Theme::icon({"download", "view-refresh"}), tr("Update Now"));
      updateNow->setToolTip(tr("Download the latest signed rules"));
      auto* reload = new QPushButton(Theme::icon({"view-refresh"}), tr("Reload"));
      reload->setToolTip(tr("Reload the rule files from disk"));
      rulesStatus_ = new QLabel;
      rulesRow->addWidget(updateNow);
      rulesRow->addWidget(reload);
      rulesRow->addStretch(1);
      form->addRow(QString(), rulesRow);
      form->addRow(QString(), rulesStatus_);
      connect(reload, &QPushButton::clicked, this, [this] { client_->reloadRules(); });
      connect(updateNow, &QPushButton::clicked, this, [this] {
        showRulesStatus_ = true;
        rulesStatus_->setText(tr("Checking for new rules"));
        client_->updateRulesNow();
      });
    }

    {
      auto* form = beginCategory(tr("Scheduled Scans"), {"appointment-new", "view-calendar"});
      scheduleType_ = new QComboBox;
      scheduleType_->addItems({tr("Off"), tr("Daily")});
      time_ = new QTimeEdit;
      time_->setDisplayFormat(QStringLiteral("HH:mm"));
      time_->setTime(QTime(3, 0));
      time_->setToolTip(tr("Scan time"));
      auto* schedRow = new QHBoxLayout;
      schedRow->addWidget(scheduleType_);
      schedRow->addWidget(time_);
      schedRow->addStretch(1);
      form->addRow(tr("Scheduled scan:"), schedRow);
      connect(scheduleType_, &QComboBox::currentIndexChanged, this, [this] {
        time_->setEnabled(scheduleType_->currentIndex() == 1);
        updateButtons();
      });
      time_->setEnabled(false);
      connect(time_, &QTimeEdit::timeChanged, this, &SettingsPage::updateButtons);
    }

    {
      auto* form = beginCategory(tr("Notifications"), {"preferences-desktop-notification", "dialog-information"});
      notify_ = check(tr("Show a message when a threat is found"));
      form->addRow(tr("Notifications:"), notify_);
    }

    {
      auto* form = beginCategory(tr("Exclusions"), {"edit-find", "view-filter"});
      excl_ = new QListWidget;
      excl_->setSelectionMode(QAbstractItemView::SingleSelection);
      excl_->setEditTriggers(QAbstractItemView::DoubleClicked | QAbstractItemView::EditKeyPressed);
      excl_->setTextElideMode(Qt::ElideMiddle);
      excl_->setToolTip(tr("Files and folders that are never scanned. Double-click to edit."));
      const int rowH = excl_->fontMetrics().height() + 2 * Theme::spacing(this);
      excl_->setFixedHeight(rowH * 5 + 2 * excl_->frameWidth());
      new Theme::Placeholder(excl_, QIcon(), tr("No exclusions"));
      form->addRow(tr("Never scan:"), excl_);
      auto* exclRow = new QHBoxLayout;
      auto* addFolder = new QPushButton(Theme::icon({"list-add"}), tr("Add Folder..."));
      auto* remove = new QPushButton(Theme::icon({"list-remove"}), tr("Remove"));
      remove->setEnabled(false);
      exclRow->addWidget(addFolder);
      exclRow->addWidget(remove);
      exclRow->addStretch(1);
      form->addRow(QString(), exclRow);

      allowExec_ = new QListWidget;
      allowExec_->setSelectionMode(QAbstractItemView::SingleSelection);
      allowExec_->setEditTriggers(QAbstractItemView::DoubleClicked | QAbstractItemView::EditKeyPressed);
      allowExec_->setTextElideMode(Qt::ElideMiddle);
      allowExec_->setToolTip(tr("Programs here may run from downloads or temp folders. Double-click to edit."));
      allowExec_->setFixedHeight(rowH * 4 + 2 * allowExec_->frameWidth());
      new Theme::Placeholder(allowExec_, QIcon(), tr("No allowed programs"));
      form->addRow(tr("Allowed to run:"), allowExec_);
      auto* allowRow = new QHBoxLayout;
      auto* addAllow = new QPushButton(Theme::icon({"list-add"}), tr("Add File..."));
      auto* remAllow = new QPushButton(Theme::icon({"list-remove"}), tr("Remove"));
      remAllow->setEnabled(false);
      allowRow->addWidget(addAllow);
      allowRow->addWidget(remAllow);
      allowRow->addStretch(1);
      form->addRow(QString(), allowRow);

      connect(excl_->model(), &QAbstractItemModel::dataChanged, this, &SettingsPage::updateButtons);
      connect(excl_, &QListWidget::itemSelectionChanged, this, [this, remove] {
        remove->setEnabled(!excl_->selectedItems().isEmpty());
      });
      connect(addFolder, &QPushButton::clicked, this, [this] {
        const QString dir = QFileDialog::getExistingDirectory(this, tr("Exclude Folder"));
        if (dir.isEmpty() || !excl_->findItems(dir, Qt::MatchExactly).isEmpty()) return;
        addExclusion(dir);
        updateButtons();
      });
      connect(remove, &QPushButton::clicked, this, [this] {
        qDeleteAll(excl_->selectedItems());
        updateButtons();
      });
      connect(allowExec_->model(), &QAbstractItemModel::dataChanged, this, &SettingsPage::updateButtons);
      connect(allowExec_, &QListWidget::itemSelectionChanged, this, [this, remAllow] {
        remAllow->setEnabled(!allowExec_->selectedItems().isEmpty());
      });
      connect(addAllow, &QPushButton::clicked, this, [this] {
        const QString f = QFileDialog::getOpenFileName(this, tr("Allow Program"));
        if (f.isEmpty() || !allowExec_->findItems(f, Qt::MatchExactly).isEmpty()) return;
        addAllowItem(f);
        updateButtons();
      });
      connect(remAllow, &QPushButton::clicked, this, [this] {
        qDeleteAll(allowExec_->selectedItems());
        updateButtons();
      });
    }

    cats_->setFixedWidth([this] {
      int w = 0;
      for (int i = 0; i < cats_->count(); ++i)
        w = qMax(w, cats_->fontMetrics().horizontalAdvance(cats_->item(i)->text()));
      return qMax(170, w + cats_->iconSize().width() + 48);
    }());

    auto* sep = new QFrame;
    sep->setFrameShape(QFrame::VLine);
    sep->setFrameShadow(QFrame::Sunken);

    auto* catSide = new QWidget;
    catSide->setBackgroundRole(QPalette::Base);
    catSide->setAutoFillBackground(true);
    auto* catLay = new QVBoxLayout(catSide);
    const int sp = Theme::spacing(this);
    catLay->setContentsMargins(sp, sp, sp, sp);
    catLay->addWidget(cats_);

    split->addWidget(catSide);
    split->addWidget(sep);
    split->addWidget(stack_, 1);
    root->addLayout(split, 1);

    buttons_ = new QDialogButtonBox(QDialogButtonBox::Reset | QDialogButtonBox::Apply);
    buttons_->button(QDialogButtonBox::Apply)->setToolTip(tr("Changing protection options needs administrator rights"));
    root->addWidget(buttons_);

    connect(cats_, &QListWidget::currentRowChanged, stack_, &QStackedWidget::setCurrentIndex);
    cats_->setCurrentRow(0);

    connect(buttons_->button(QDialogButtonBox::Apply), &QPushButton::clicked, this, &SettingsPage::save);
    connect(buttons_->button(QDialogButtonBox::Reset), &QPushButton::clicked, this, [this] {
      apply(loaded_);
      updateButtons();
    });

    connect(client_, &DaemonClient::configLoaded, this, &SettingsPage::load);
    connect(client_, &DaemonClient::statusUpdated, this, &SettingsPage::loadProtection);
    connect(client_, &DaemonClient::rulesUpdated, this, &SettingsPage::showRules);
    connect(client_, &DaemonClient::actionDone, this,
            [this](const QString& what, bool ok, const QString& err) {
      if (what == QLatin1String("updateRules") && !ok)
        rulesStatus_->setText(tr("Update failed: %1").arg(err));
    });
    updateButtons();
  }

  bool notificationsEnabled() const { return notify_->isChecked(); }

signals:
  void notificationsToggled(bool enabled);

private:
  QFormLayout* beginCategory(const QString& name, const QStringList& icons) {
    auto* item = new QListWidgetItem(Theme::icon(icons), name);
    const int sp = Theme::spacing(this);
    item->setSizeHint(QSize(0, cats_->iconSize().height() + 2 * sp + 6));
    cats_->addItem(item);

    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    auto* body = new QWidget;
    body->setAutoFillBackground(false);
    scroll->viewport()->setAutoFillBackground(false);
    auto* bodyLay = new QVBoxLayout(body);
    const int m = Theme::pageMargin(this);
    bodyLay->setContentsMargins(m, m, m, m);
    auto* head = new QLabel(name);
    head->setFont(Theme::scaledFont(head->font(), 1.3, true));
    bodyLay->addWidget(head);
    bodyLay->addSpacing(sp * 2);
    auto* form = Theme::form(this);
    form->setVerticalSpacing(sp * 2);
    bodyLay->addLayout(form);
    bodyLay->addStretch(1);
    scroll->setWidget(body);
    stack_->addWidget(scroll);
    return form;
  }

  void addExclusion(const QString& path) {
    auto* it = new QListWidgetItem(path, excl_);
    it->setFlags(it->flags() | Qt::ItemIsEditable);
    it->setToolTip(path);
  }
  void addAllowItem(const QString& path) {
    auto* it = new QListWidgetItem(path, allowExec_);
    it->setFlags(it->flags() | Qt::ItemIsEditable);
    it->setToolTip(path);
  }

  QJsonObject state() const {
    QJsonArray excl;
    for (int i = 0; i < excl_->count(); ++i) {
      const QString t = excl_->item(i)->text().trimmed();
      if (!t.isEmpty()) excl.append(t);
    }
    QJsonArray allow;
    for (int i = 0; i < allowExec_->count(); ++i) {
      const QString t = allowExec_->item(i)->text().trimmed();
      if (!t.isEmpty()) allow.append(t);
    }
    return QJsonObject{
      {"fileRealtime", fileRt_->isChecked()},
      {"processWatch", proc_->isChecked()},
      {"networkWatch", net_->isChecked()},
      {"onAccessBlocking", onAccess_->isChecked()},
      {"killMalicious", kill_->isChecked()},
      {"networkBlocking", netBlock_->isChecked()},
      {"clamavEnabled", clam_->isChecked()},
      {"rulesAutoUpdate", autoUpd_->isChecked()},
      {"ransomShield", ransom_->isChecked()},
      {"execProtection", exec_->isChecked()},
      {"persistenceGuard", persist_->isChecked()},
      {"revShellWatch", revshell_->isChecked()},
      {"privEscWatch", privesc_->isChecked()},
      {"fileScanMaxFileMb", maxMb_->value()},
      {"scheduleType", scheduleType_->currentIndex() == 1 ? "daily" : "none"},
      {"scheduleHour", time_->time().hour()},
      {"scheduleMinute", time_->time().minute()},
      {"notifications", notify_->isChecked()},
      {"exclusions", excl},
      {"execAllowList", allow},
    };
  }

  static QJsonObject pick(const QJsonObject& o, std::initializer_list<const char*> keys) {
    QJsonObject r;
    for (const char* k : keys) r.insert(QLatin1String(k), o.value(QLatin1String(k)));
    return r;
  }

  void apply(const QJsonObject& s) {
    fileRt_->setChecked(s.value("fileRealtime").toBool(true));
    proc_->setChecked(s.value("processWatch").toBool(true));
    net_->setChecked(s.value("networkWatch").toBool(true));
    onAccess_->setChecked(s.value("onAccessBlocking").toBool(true));
    kill_->setChecked(s.value("killMalicious").toBool(true));
    netBlock_->setChecked(s.value("networkBlocking").toBool(true));
    clam_->setChecked(s.value("clamavEnabled").toBool(true));
    autoUpd_->setChecked(s.value("rulesAutoUpdate").toBool(true));
    ransom_->setChecked(s.value("ransomShield").toBool(true));
    exec_->setChecked(s.value("execProtection").toBool(true));
    persist_->setChecked(s.value("persistenceGuard").toBool(true));
    revshell_->setChecked(s.value("revShellWatch").toBool(true));
    privesc_->setChecked(s.value("privEscWatch").toBool(true));
    maxMb_->setValue(qBound(1, s.value("fileScanMaxFileMb").toInt(200), 4096));
    scheduleType_->setCurrentIndex(s.value("scheduleType").toString() == QLatin1String("daily") ? 1 : 0);
    time_->setTime(QTime(qBound(0, s.value("scheduleHour").toInt(3), 23),
                         qBound(0, s.value("scheduleMinute").toInt(0), 59)));
    notify_->setChecked(s.value("notifications").toBool(true));
    excl_->clear();
    for (const auto& v : s.value("exclusions").toArray()) addExclusion(v.toString());
    allowExec_->clear();
    for (const auto& v : s.value("execAllowList").toArray()) addAllowItem(v.toString());
  }

  void updateButtons() {
    const bool dirty = !loaded_.isEmpty() && state() != loaded_;
    buttons_->button(QDialogButtonBox::Apply)->setEnabled(dirty);
    buttons_->button(QDialogButtonBox::Reset)->setEnabled(dirty);
  }

  void load(const QJsonObject& cfg) {
    const QJsonObject cur = state();
    QJsonObject next = loaded_.isEmpty() ? cur : loaded_;
    QJsonArray excl;
    for (const auto& v : cfg.value("exclusions").toArray()) excl.append(v.toString());
    next["exclusions"] = excl;
    QJsonArray allow;
    for (const auto& v : cfg.value("execAllowList").toArray()) allow.append(v.toString());
    next["execAllowList"] = allow;
    next["scheduleType"] = cfg.value("scheduleType").toString("none");
    next["scheduleHour"] = qMax(0, cfg.value("scheduleHour").toInt(3));
    next["scheduleMinute"] = cfg.value("scheduleMinute").toInt(0);
    next["fileScanMaxFileMb"] = cfg.value("fileScanMaxFileMb").toInt(200);
    for (const char* k : {"onAccessBlocking", "killMalicious", "networkBlocking", "clamavEnabled",
                          "rulesAutoUpdate", "ransomShield", "execProtection", "persistenceGuard",
                          "revShellWatch", "privEscWatch"})
      next[QLatin1String(k)] = cfg.value(QLatin1String(k)).toBool(true);
    next["notifications"] = loaded_.value("notifications").toBool(true);
    replaceLoaded(next);
  }

  void loadProtection(const QJsonObject& s) {
    if (!s.contains("fileRealtime")) return;
    QJsonObject next = loaded_.isEmpty() ? state() : loaded_;
    if (loaded_.isEmpty()) next["notifications"] = true;
    next["fileRealtime"] = s.value("fileRealtime").toBool(true);
    next["processWatch"] = s.value("processWatch").toBool(true);
    next["networkWatch"] = s.value("networkWatch").toBool(true);
    if (s.contains("rules") && !showRulesStatus_) showRules(s.value("rules").toObject());
    replaceLoaded(next);
  }

  void replaceLoaded(const QJsonObject& next) {
    const QJsonObject cur = state();
    QJsonObject merged = next;
    if (!loaded_.isEmpty()) {
      for (auto it = cur.begin(); it != cur.end(); ++it)
        if (it.value() != loaded_.value(it.key())) merged[it.key()] = it.value();
    }
    loaded_ = next;
    if (merged != cur) apply(merged);
    updateButtons();
  }

  void showRules(const QJsonObject& r) {
    if (r.value("running").toBool()) {
      rulesStatus_->setText(tr("Checking for new rules"));
      return;
    }
    const QString err = r.value("lastError").toString();
    if (!err.isEmpty()) rulesStatus_->setText(tr("Update failed: %1").arg(err));
    else if (showRulesStatus_)
      rulesStatus_->setText(tr("Version %1, checked %2")
        .arg(r.value("version").toVariant().toLongLong())
        .arg(Theme::when(r.value("lastCheck").toVariant().toLongLong())));
    else rulesStatus_->clear();
    rulesStatus_->setToolTip(r.value("lastResult").toString());
  }

  void save() {
    const QJsonObject s = state();
    client_->setConfig(pick(s, {"exclusions", "execAllowList", "scheduleType", "scheduleHour", "scheduleMinute"}));
    const QStringList optKeys = {"onAccessBlocking", "killMalicious", "networkBlocking", "clamavEnabled",
                                 "rulesAutoUpdate", "ransomShield", "execProtection", "persistenceGuard",
                                 "revShellWatch", "privEscWatch", "fileScanMaxFileMb"};
    QJsonObject f, fLoaded;
    for (const auto& k : optKeys) { f[k] = s.value(k); fLoaded[k] = loaded_.value(k); }
    if (f != fLoaded) client_->setOptions(f);
    const QJsonObject p = pick(s, {"fileRealtime", "processWatch", "networkWatch"});
    if (p != pick(loaded_, {"fileRealtime", "processWatch", "networkWatch"}))
      client_->setProtection(fileRt_->isChecked(), proc_->isChecked(), net_->isChecked());
    if (s.value("notifications") != loaded_.value("notifications"))
      emit notificationsToggled(notify_->isChecked());
    loaded_ = s;
    updateButtons();
  }

  DaemonClient* client_;
  QListWidget* cats_;
  QStackedWidget* stack_;
  QCheckBox* fileRt_;
  QCheckBox* onAccess_;
  QCheckBox* proc_;
  QCheckBox* kill_;
  QCheckBox* net_;
  QCheckBox* netBlock_;
  QCheckBox* clam_;
  QCheckBox* autoUpd_;
  QCheckBox* ransom_;
  QCheckBox* exec_;
  QCheckBox* persist_;
  QCheckBox* revshell_;
  QCheckBox* privesc_;
  QSpinBox* maxMb_;
  QComboBox* scheduleType_;
  QTimeEdit* time_;
  QCheckBox* notify_;
  QListWidget* excl_;
  QListWidget* allowExec_;
  QLabel* rulesStatus_;
  QDialogButtonBox* buttons_;
  QJsonObject loaded_;
  bool showRulesStatus_{false};
};
