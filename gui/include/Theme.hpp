#pragma once
// Small helpers that only use the active QStyle and system palette.
// No colors, fonts, or stylesheets are injected here.
#include <QApplication>
#include <QStyleFactory>
#include <QStyle>
#include <QIcon>
#include <QFont>
#include <QLabel>
#include <QPalette>
#include <QString>
#include <QStringList>
#include <QWidget>
#include <QVBoxLayout>
#include <QBoxLayout>
#include <QAbstractItemView>
#include <QAbstractItemModel>
#include <QTreeView>
#include <QHeaderView>
#include <QEvent>
#include <QFormLayout>
#include <QDateTime>
#include <QLocale>

namespace Theme {

// Under Plasma the platform theme already picks Breeze and the user's
// palette and icon theme. Elsewhere, fall back to Breeze (if installed)
// or Fusion, and make sure freedesktop icon names still resolve.
inline void applyStyle(QApplication& app) {
  const QString current = app.style() ? app.style()->name() : QString();
  if (current.compare(QLatin1String("breeze"), Qt::CaseInsensitive) != 0 &&
      QStyleFactory::keys().contains(QLatin1String("Breeze"), Qt::CaseInsensitive))
    app.setStyle(QStringLiteral("Breeze"));
  // Without Breeze, keep whatever the platform picked (Fusion by default).
  if (QIcon::themeName().isEmpty() || QIcon::themeName() == QLatin1String("hicolor"))
    QIcon::setThemeName(QStringLiteral("breeze"));
  QIcon::setFallbackThemeName(QStringLiteral("breeze"));
}

// QIcon::fromTheme with a chain of freedesktop fallbacks.
inline QIcon icon(const QStringList& names) {
  for (const QString& n : names) {
    if (QIcon::hasThemeIcon(n))
      return QIcon::fromTheme(n);
  }
  return names.isEmpty() ? QIcon() : QIcon::fromTheme(names.first());
}

inline QFont scaledFont(const QFont& base, qreal scale, bool bold = false) {
  QFont f = base;
  if (f.pointSizeF() > 0)
    f.setPointSizeF(f.pointSizeF() * scale);
  else if (f.pixelSize() > 0)
    f.setPixelSize(qRound(f.pixelSize() * scale));
  f.setBold(bold);
  return f;
}

// Secondary text drawn in the palette's placeholder color.
inline void makeSecondary(QWidget* w) {
  QPalette p = w->palette();
  for (auto group : {QPalette::Active, QPalette::Inactive}) {
    const QColor c = p.color(group, QPalette::PlaceholderText);
    p.setColor(group, QPalette::WindowText, c);
    p.setColor(group, QPalette::Text, c);
  }
  w->setPalette(p);
}

inline int margin(const QWidget* w = nullptr) {
  const QStyle* s = w ? w->style() : QApplication::style();
  QStyleOption opt;
  opt.state |= QStyle::State_Window;
  const int v = s->pixelMetric(QStyle::PM_LayoutLeftMargin, &opt, nullptr);
  return v > 0 ? v : 10;
}

inline int spacing(const QWidget* w = nullptr) {
  const QStyle* s = w ? w->style() : QApplication::style();
  const int v = s->pixelMetric(QStyle::PM_LayoutVerticalSpacing, nullptr, w);
  return v > 0 ? v : 6;
}

inline int sectionSpacing(const QWidget* w = nullptr) { return spacing(w) * 3; }

inline void addSectionGap(QBoxLayout* lay, const QWidget* w = nullptr) {
  lay->addSpacing(sectionSpacing(w) - spacing(w));
}

inline int pageMargin(const QWidget* w = nullptr) { return margin(w) * 2; }

inline QFormLayout* form(const QWidget* w = nullptr) {
  auto* f = new QFormLayout;
  f->setContentsMargins(0, 0, 0, 0);
  f->setHorizontalSpacing(spacing(w));
  f->setVerticalSpacing(spacing(w));
  f->setRowWrapPolicy(QFormLayout::DontWrapRows);
  f->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
  f->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
  f->setFormAlignment(Qt::AlignLeft | Qt::AlignTop);
  return f;
}

inline void setupView(QTreeView* v) {
  v->setRootIsDecorated(false);
  v->setUniformRowHeights(true);
  v->setAlternatingRowColors(false);
  v->setSelectionBehavior(QAbstractItemView::SelectRows);
  v->setSelectionMode(QAbstractItemView::SingleSelection);
  v->setEditTriggers(QAbstractItemView::NoEditTriggers);
  v->setTextElideMode(Qt::ElideMiddle);
  v->header()->setSectionsMovable(false);
  v->header()->setHighlightSections(false);
}

class Placeholder : public QWidget {
public:
  Placeholder(QAbstractItemView* view, const QIcon& icon, const QString& text)
    : QWidget(view->viewport()), view_(view) {
    setAttribute(Qt::WA_TransparentForMouseEvents);
    auto* lay = new QVBoxLayout(this);
    lay->setSpacing(spacing(this) * 2);
    lay->addStretch(1);
    auto* pic = new QLabel;
    pic->setAlignment(Qt::AlignCenter);
    const int sz = style()->pixelMetric(QStyle::PM_LargeIconSize, nullptr, this) * 2;
    pic->setPixmap(icon.pixmap(QSize(sz, sz), devicePixelRatioF(), QIcon::Disabled));
    lay->addWidget(pic);
    text_ = new QLabel(text);
    text_->setAlignment(Qt::AlignCenter);
    text_->setWordWrap(true);
    text_->setFont(scaledFont(text_->font(), 1.2));
    makeSecondary(text_);
    lay->addWidget(text_);
    lay->addStretch(1);
    view->viewport()->installEventFilter(this);
    auto* m = view->model();
    connect(m, &QAbstractItemModel::rowsInserted, this, [this] { refresh(); });
    connect(m, &QAbstractItemModel::rowsRemoved, this, [this] { refresh(); });
    connect(m, &QAbstractItemModel::modelReset, this, [this] { refresh(); });
    connect(m, &QAbstractItemModel::layoutChanged, this, [this] { refresh(); });
    setGeometry(view->viewport()->rect());
    refresh();
  }

  void setText(const QString& t) { text_->setText(t); }

protected:
  bool eventFilter(QObject* o, QEvent* e) override {
    if (o == view_->viewport() && e->type() == QEvent::Resize)
      setGeometry(view_->viewport()->rect());
    return QWidget::eventFilter(o, e);
  }

private:
  void refresh() {
    const bool empty = view_->model()->rowCount() == 0;
    setVisible(empty);
    if (auto* tv = qobject_cast<QTreeView*>(view_)) tv->header()->setHidden(empty);
  }

  QAbstractItemView* view_;
  QLabel* text_;
};

// Icon for a rule severity string, from the standard dialog icons.
inline QIcon severityIcon(const QString& sev) {
  if (sev == QLatin1String("critical") || sev == QLatin1String("high"))
    return icon({"dialog-error", "security-low"});
  if (sev == QLatin1String("medium"))
    return icon({"dialog-warning", "security-medium"});
  return icon({"dialog-information", "help-about"});
}

inline QString capitalized(const QString& sev) {
  if (sev.isEmpty()) return QObject::tr("Unknown");
  QString s = sev;
  s[0] = s[0].toUpper();
  return s;
}

inline QString when(qint64 secs) {
  if (secs <= 0) return QObject::tr("Never");
  return QLocale().toString(QDateTime::fromSecsSinceEpoch(secs), QLocale::ShortFormat);
}

} // namespace Theme
