#include <QtCore>
#include <QtGui>
#include <QtWidgets>
#include <QtQml>

#include "clamav.h"

#include <filesystem>
#include <future>
#include <iostream>
#include <utility>

typedef struct cl_scan_options scanopts;

void run_clamav_daemon();
std::pair<int, const char*> check_virus(const char *filename, struct cl_engine* clamav, scanopts &options);

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
	}
	if ((success = cl_load(cl_retdbdir(), clamav, &sigs, CL_DB_STDOPT)) != CL_SUCCESS) {
		std::cout << "Failed to initialize ClamAV DB!" << std::endl;
		cl_engine_free(clamav);
		return;
	}
	std::cout << "Initialized ClamAV DB" << std::endl;
	cl_engine_compile(clamav);

	scanopts options;
	memset(&options, CL_SCAN_GENERAL_ALLMATCHES, sizeof(scanopts));

	auto a = check_virus("/tmp/test.txt", clamav, options);
	if (a.first == 1)
		std::cout << "Virus detected: " << a.second << std::endl;
	else if (a.first == 2)
		std::cerr << "Error: " << a.second << std::endl;
	else std::cout << "No viruses detected." << std::endl;
}

std::pair<int, const char*> check_virus(const char *filename, struct cl_engine* clamav, scanopts &options) {
	cl_error_t success;
	const char *virname;

	if ((success = cl_scanfile(filename, &virname, NULL, clamav, &options)) == CL_VIRUS)
		return std::pair(1, virname);
	else if (success != CL_CLEAN)
		return std::pair(2, cl_strerror(success));
	else
		return std::pair(0, (const char*)NULL);
}
