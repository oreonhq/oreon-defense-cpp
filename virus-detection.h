#ifndef __VIRUS_DETECTION_H__

#define __VIRUS_DETECTION_H__

#include <QtQml>
#include <QObject>
#include <QVariant>
#include <QtQmlIntegration/qqmlintegration.h>
#include <utility>
#include <future>
#include <cstdlib>
#include <iostream>
#include "clamav.h"


typedef struct cl_scan_options scanopts;
typedef struct cl_engine* daemon;

std::pair<daemon, scanopts> run_clamav_daemon();
std::pair<int, const char*> check_virus(const char *filename, struct cl_engine* clamav, scanopts &options);

class Antivirus : public QObject {
	Q_OBJECT
	QML_ELEMENT
	QML_SINGLETON

public:
	Antivirus(QObject *parent = nullptr) : QObject(parent) {
		//clamav_daemon = a.first;
		//options = a.second;
	}

	Q_INVOKABLE QVariantMap checkVirus(QString file) {
		auto a = check_virus(file.toUtf8(), clamav_daemon, options);
		QVariantMap b;
		b["success"] = a.first;
		if (a.first != 0) b["value"] = a.second;
		return b;
	}
private:
	inline static daemon clamav_daemon;
	inline static scanopts options;
public:
	static void run_clamav_daemon() {
		int success;

		success = cl_init(CL_INIT_DEFAULT);
		std::cout << (success == CL_SUCCESS ? "Initialized ClamAV" : "Failed to initialize ClamAV!") << std::endl;

		daemon clamav;
		unsigned int sigs = 0;

		if (!(clamav = cl_engine_new())) {
			std::cout << "Failed to create ClamAV engine!" << std::endl;
			cl_engine_free(clamav);
			std::exit(1);
		}
		if ((success = cl_load(cl_retdbdir(), clamav, &sigs, CL_DB_STDOPT)) != CL_SUCCESS) {
			std::cout << "Failed to initialize ClamAV DB!" << std::endl;
			cl_engine_free(clamav);
			std::exit(1);
		}
		std::cout << "Initialized ClamAV DB" << std::endl;
		cl_engine_compile(clamav);

		scanopts opts;
		memset(&opts, CL_SCAN_GENERAL_ALLMATCHES, sizeof(scanopts));

		clamav_daemon = clamav;
		options = opts;
	}
};


#endif // __VIRUS_DETECTION_H__
