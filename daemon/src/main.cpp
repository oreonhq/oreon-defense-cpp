#include "Daemon.hpp"
#include <iostream>
#include <string>

int main(int argc, char** argv) {
  std::string configPath;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--config" && i + 1 < argc) configPath = argv[++i];
    else if (a == "--help" || a == "-h") {
      std::cout << "oreon-defense-daemon [--config PATH]\n";
      return 0;
    }
  }

  oreon::Daemon daemon;
  if (!daemon.init(configPath)) {
    std::cerr << "daemon init failed\n";
    return 1;
  }
  return daemon.run();
}
