#include "Quarantine.hpp"
#include <oreon/Types.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;

int main() {
  const std::string base = "/tmp/oreon-defense-qtest-" + std::to_string(oreon::nowEpoch());
  fs::create_directories(base + "/src");
  const std::string src = base + "/src/evil.txt";
  {
    std::ofstream out(src);
    out << "payload";
  }

  oreon::Quarantine q;
  q.setDir(base + "/quarantine");

  oreon::Threat t;
  t.name = "Test threat";
  t.severity = oreon::Severity::High;
  auto item = q.quarantineFile(src, t);
  if (!item) {
    std::cerr << "fail quarantine\n";
    return 1;
  }
  if (fs::exists(src)) {
    std::cerr << "fail source still present\n";
    return 1;
  }
  if (q.list().size() != 1) {
    std::cerr << "fail list size\n";
    return 1;
  }
  if (!q.restore(item->id)) {
    std::cerr << "fail restore\n";
    return 1;
  }
  if (!fs::exists(src)) {
    std::cerr << "fail restored missing\n";
    return 1;
  }
  // quarantine again and delete
  item = q.quarantineFile(src, t);
  if (!item || !q.remove(item->id)) {
    std::cerr << "fail delete\n";
    return 1;
  }
  fs::remove_all(base);
  std::cout << "ok\n";
  return 0;
}
