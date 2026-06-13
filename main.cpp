#include <QtCore>
#include <QtGui>
#include <QtWidgets>
#include <QtQml>

#include <filesystem>
#include <future>
#include <iostream>

#include "virus-detection.h"

int main(int argc, char** argv) {
	QApplication app(argc, argv);
	std::cout << "App initialized" << std::endl;


	QQmlApplicationEngine engine; //("ui/Main.qml");
	QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed,
					 &app, []() { QCoreApplication::exit(-1); },
					 Qt::QueuedConnection);
	engine.loadFromModule("MainUi", "Main");

	// for (const auto& entry : std::filesystem::directory_iterator("ui/pages")) {
	// 	std::cout << entry.path() << std::endl;
	// }
	
	std::cout << "About to execute" << std::endl;

	auto a = std::async(Antivirus::run_clamav_daemon);

	return app.exec();
}
