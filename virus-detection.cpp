#include "virus-detection.h"

#include <cstdlib>
#include <iostream>
#include <utility>

std::pair<daemon, scanopts> run_clamav_daemon() {
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

	scanopts options;
	memset(&options, CL_SCAN_GENERAL_ALLMATCHES, sizeof(scanopts));

	return std::pair(clamav, options);
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
