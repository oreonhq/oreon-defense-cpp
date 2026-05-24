#include <QtCore>
#include <QtGui>
#include <QtWidgets>
#include <QtQml>

#include <iostream>
#include <filesystem>

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
	return app.exec();
}
