#include <QtCore>
#include <QtGui>
#include <QtWidgets>
#include <QtQml>

#include "clamav.h"

#include <iostream>
#include <filesystem>
#include <future>

void run_clamav_daemon();

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

	auto a = std::async(run_clamav_daemon);

	return app.exec();
}

void run_clamav_daemon() {
	int success;

	success = cl_init(CL_INIT_DEFAULT);
	std::cout << (success == CL_SUCCESS ? "Initialized ClamAV" : "Failed to initialize ClamAV!") << std::endl;

	struct cl_engine* clamav;
	unsigned int sigs = 0;

	if (!(clamav = cl_engine_new())) {
		std::cout << "Failed to create ClamAV engine!" << std::endl;
		cl_engine_free(clamav);
		return;
	} else {
		success = cl_load(cl_retdbdir(), clamav, &sigs, CL_DB_STDOPT);
		if (success != CL_SUCCESS) {
			std::cout << "Failed to initialize ClamAV DB!" << std::endl;
			cl_engine_free(clamav);
			return;
		} else {
			std::cout << "Initialized ClamAV DB" << std::endl;
		}
	}
}
