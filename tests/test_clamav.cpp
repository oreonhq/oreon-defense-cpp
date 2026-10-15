#include "ClamEngine.hpp"
#include <iostream>
#include <filesystem>

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cerr << "usage: test_clamav EICAR_FILE DBDIR\n";
    return 2;
  }
  std::string eicar = argv[1], db = argv[2];
  bool haveDb = false;
  std::error_code ec;
  for (const char* f : {"/main.cvd", "/main.cld", "/daily.cvd", "/daily.cld"})
    if (std::filesystem::exists(db + f, ec)) haveDb = true;
  oreon::ClamEngine eng;
  eng.setDbDir(db);
  if (!haveDb) {
    bool ok = eng.loadNow();
    auto st = eng.status();
    std::cout << "no database: load=" << ok << " error=\"" << st.error << "\"\n";
    if (ok || st.error.empty()) return 1;
    return 77;
  }
  if (!eng.loadNow()) {
    std::cerr << "load failed: " << eng.status().error << "\n";
    return 1;
  }
  auto st = eng.status();
  std::cout << "libclamav " << st.libVersion << " sigs=" << st.signatures
            << " daily=" << st.dailyVersion << " main=" << st.mainVersion << "\n";
  auto r = eng.scanFile(eicar);
  if (!r.infected) {
    std::cerr << "EICAR not detected: " << r.message << "\n";
    return 1;
  }
  std::cout << "EICAR detected as " << r.virusName << "\n";
  auto clean = eng.scanFile(argv[0]);
  if (clean.infected) {
    std::cerr << "false positive on test binary: " << clean.virusName << "\n";
    return 1;
  }
  std::cout << "test_clamav: ok\n";
  return 0;
}
