#include "Daemon.hpp"
#include "Signature.hpp"
#include <iostream>
#include <string>
#include <csignal>

static int verifyCmd(const std::string& key, const std::string& file, const std::string& sig) {
  std::string pem, data, s, err;
  if (!oreon::readWholeFile(key, pem) || !oreon::readWholeFile(file, data) ||
      !oreon::readWholeFile(sig, s)) {
    std::cerr << "cannot read input files\n";
    return 2;
  }
  if (!oreon::verifyEd25519(pem, data, s, &err)) {
    std::cerr << "BAD signature: " << err << "\n";
    return 1;
  }
  std::cout << "signature ok\n";
  return 0;
}

int main(int argc, char** argv) {
  std::string configPath;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--config" && i + 1 < argc) configPath = argv[++i];
    else if (a == "--verify-rules" && i + 3 < argc) {
      return verifyCmd(argv[i + 1], argv[i + 2], argv[i + 3]);
    } else if (a == "--version") {
      std::cout << "oreon-defense-daemon " OREON_VERSION "\n";
      return 0;
    } else if (a == "--help" || a == "-h") {
      std::cout << "oreon-defense-daemon [--config PATH]\n"
                   "oreon-defense-daemon --verify-rules PUBKEY.pem rules.yaml rules.yaml.sig\n"
                   "oreon-defense-daemon --version\n";
      return 0;
    }
  }
  std::signal(SIGPIPE, SIG_IGN);

  oreon::Daemon daemon;
  if (!daemon.init(configPath)) {
    std::cerr << "daemon init failed\n";
    return 1;
  }
  return daemon.run();
}
