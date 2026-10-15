#include <QApplication>
#include <QCommandLineParser>
#include <QLocalServer>
#include <QLocalSocket>
#include <unistd.h>
#include "MainWindow.hpp"
#include "Theme.hpp"

int main(int argc, char* argv[]) {
  QApplication app(argc, argv);
  QApplication::setApplicationName("Oreon Defense");
  QApplication::setOrganizationName("Oreon");
  QApplication::setApplicationVersion(QStringLiteral(OREON_VERSION));
  QApplication::setDesktopFileName("oreon-defense");

  Theme::applyStyle(app);

  QCommandLineParser parser;
  parser.setApplicationDescription("Security app for Oreon with real-time protection and alerts.");
  parser.addHelpOption();
  parser.addVersionOption();
  QCommandLineOption sockOpt(QStringList() << "s" << "socket",
    "Daemon socket path", "path");
  parser.addOption(sockOpt);
  QCommandLineOption trayOpt(QStringList() << "t" << "tray",
    "Start hidden in the system tray");
  parser.addOption(trayOpt);
  parser.process(app);

  const QString lockName = QStringLiteral("oreon-defense-gui-%1").arg(getuid());
  {
    QLocalSocket probe;
    probe.connectToServer(lockName);
    if (probe.waitForConnected(500)) {
      if (!parser.isSet(trayOpt)) {
        probe.write("show\n");
        probe.waitForBytesWritten(500);
      }
      probe.disconnectFromServer();
      return 0;
    }
  }
  QLocalServer server;
  server.setSocketOptions(QLocalServer::UserAccessOption);
  if (!server.listen(lockName)) {
    QLocalServer::removeServer(lockName);
    server.listen(lockName);
  }

  MainWindow w;
  QObject::connect(&server, &QLocalServer::newConnection, &w, [&server, &w] {
    while (QLocalSocket* c = server.nextPendingConnection()) {
      QObject::connect(c, &QLocalSocket::readyRead, &w, [c, &w] {
        if (c->readAll().startsWith("show")) w.showMain();
      });
      QObject::connect(c, &QLocalSocket::disconnected, c, &QObject::deleteLater);
    }
  });
  if (parser.isSet(trayOpt)) {
    w.startInTray();
  } else {
    w.show();
  }
  return app.exec();
}
