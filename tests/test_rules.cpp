#include "RuleEngine.hpp"
#include <iostream>
#include <string>

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cerr << "usage: test_rules RULES.yaml SAMPLES_DIR\n";
    return 2;
  }
  oreon::RuleEngine eng;
  if (!eng.loadFile(argv[1])) {
    std::cerr << "fail load rules\n";
    return 1;
  }
  if (eng.ruleCount() < 3) {
    std::cerr << "fail expected rules\n";
    return 1;
  }
  std::string samples = argv[2];
  auto eicar = eng.matchFile(samples + "/eicar.com");
  if (!eicar.matched) {
    std::cerr << "fail eicar not matched\n";
    return 1;
  }
  std::cout << "eicar matched by " << eicar.rule.id << "\n";

  auto demo = eng.matchFile(samples + "/oreon_demo_malware.sh");
  if (!demo.matched) {
    std::cerr << "fail demo malware not matched\n";
    return 1;
  }
  std::cout << "demo matched by " << demo.rule.id << "\n";

  auto miner = eng.matchFile(samples + "/suspicious_miner_payload");
  if (!miner.matched) {
    std::cerr << "fail miner fixture not matched\n";
    return 1;
  }
  std::cout << "miner matched by " << miner.rule.id << "\n";

  auto proc = eng.matchProcess("xmrig", "/usr/bin/xmrig --donate-level 0", "/tmp/xmrig");
  if (!proc.matched) {
    std::cerr << "fail process pattern\n";
    return 1;
  }
  std::cout << "process matched by " << proc.rule.id << "\n";
  std::cout << "ok\n";
  return 0;
}
