#include <QApplication>
#include <QCommandLineParser>
#include "MainWindow.hpp"
#include "Theme.hpp"

int main(int argc, char* argv[]) {
  QApplication app(argc, argv);
  QApplication::setApplicationName("Oreon Defense");
  QApplication::setOrganizationName("Oreon");
  QApplication::setApplicationVersion("1.0.3");
  QApplication::setDesktopFileName("oreon-defense");

  Theme::applyStyle(app);

  QCommandLineParser parser;
  parser.setApplicationDescription("A security app for Oreon. Straightforward protection and visibility with real-time alerts.");
  parser.addHelpOption();
  parser.addVersionOption();
  QCommandLineOption sockOpt(QStringList() << "s" << "socket",
    "Daemon socket path", "path");
  parser.addOption(sockOpt);
  QCommandLineOption trayOpt(QStringList() << "t" << "tray",
    "Start hidden in the system tray");
  parser.addOption(trayOpt);
  parser.process(app);

  MainWindow w;
  if (parser.isSet(trayOpt)) {
    w.startInTray();
  } else {
    w.show();
  }
  return app.exec();
}
