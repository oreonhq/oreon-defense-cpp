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

// Bold title scaled from the widget's own font.
inline QFont titleFont(const QFont& base, qreal scale = 1.0) {
  QFont f = base;
  if (f.pointSizeF() > 0)
    f.setPointSizeF(f.pointSizeF() * scale);
  else if (f.pixelSize() > 0)
    f.setPixelSize(qRound(f.pixelSize() * scale));
  f.setBold(true);
  return f;
}

inline QLabel* heading(const QString& text, qreal scale = 1.2) {
  auto* l = new QLabel(text);
  l->setFont(titleFont(l->font(), scale));
  return l;
}

// Secondary text drawn in the palette's placeholder color.
inline void makeSecondary(QWidget* w) {
  QPalette p = w->palette();
  const QColor c = p.color(QPalette::Active, QPalette::PlaceholderText);
  p.setColor(QPalette::Active, QPalette::WindowText, c);
  p.setColor(QPalette::Inactive, QPalette::WindowText, c);
  p.setColor(QPalette::Active, QPalette::Text, c);
  p.setColor(QPalette::Inactive, QPalette::Text, c);
  w->setPalette(p);
}

inline QLabel* secondaryLabel(const QString& text) {
  auto* l = new QLabel(text);
  l->setWordWrap(true);
  makeSecondary(l);
  return l;
}

// Standard spacing from the active style.
inline int spacing(const QWidget* w = nullptr) {
  const QStyle* s = w ? w->style() : QApplication::style();
  int v = s->pixelMetric(QStyle::PM_LayoutVerticalSpacing, nullptr, w);
  return v > 0 ? v : 6;
}

inline int margin(const QWidget* w = nullptr) {
  const QStyle* s = w ? w->style() : QApplication::style();
  int v = s->pixelMetric(QStyle::PM_LayoutLeftMargin, nullptr, w);
  return v > 0 ? v : 10;
}

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

} // namespace Theme
