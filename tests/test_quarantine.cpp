#include "Quarantine.hpp"
#include <oreon/Types.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <unistd.h>

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
  if ((fs::status(item->dataPath).permissions() & fs::perms::all) != fs::perms::none) {
    std::cerr << "fail permissions not stripped\n";
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
  if ((fs::status(src).permissions() & fs::perms::owner_read) == fs::perms::none) {
    std::cerr << "fail restored mode\n";
    return 1;
  }
  {
    std::string err;
    if (q.quarantineFile(base + "/src/missing", t, &err) || err.empty()) {
      std::cerr << "fail missing file\n";
      return 1;
    }
  }
  if (fs::exists("/dev/shm")) {
    const std::string shm = "/dev/shm/oreon-qtest-" + std::to_string(oreon::nowEpoch());
    { std::ofstream o(shm); o << "x"; }
    std::string err;
    const std::string dst = base + "/moved.bin";
    if (!oreon::Quarantine::moveFile(shm, dst, 0, &err) || fs::exists(shm) || !fs::exists(dst)) {
      std::cerr << "fail cross fs move: " << err << "\n";
      fs::remove(shm);
      return 1;
    }
  }
  if (::geteuid() != 0) {
    const std::string ro = base + "/ro";
    fs::create_directories(ro);
    { std::ofstream o(ro + "/f"); o << "y"; }
    fs::permissions(ro, fs::perms::owner_read | fs::perms::owner_exec);
    std::string err;
    auto bad = q.quarantineFile(ro + "/f", t, &err);
    fs::permissions(ro, fs::perms::owner_all);
    if (bad || err.empty() || !fs::exists(ro + "/f") || q.list().size() != 0) {
      std::cerr << "fail read only source\n";
      return 1;
    }
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
