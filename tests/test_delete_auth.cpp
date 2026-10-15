#include "PeerAuth.hpp"
#include <oreon/Types.hpp>
#include <unistd.h>
#include <iostream>

using namespace oreon;
static int failures = 0;
static void check(bool c, const char* m) { if (!c) { std::cerr << "FAIL: " << m << "\n"; ++failures; } }

int main() {
  PeerAuth auth;
  Peer root; root.uid = 0; root.pid = 10; root.startTime = 1;
  check(auth.isOwnerOrRoot(root), "root owner-or-root");

  Peer me; me.uid = getuid(); me.pid = getpid(); me.startTime = 1;
  bool active = auth.isActiveLocalSession(me);
  std::string rt = "/run/user/" + std::to_string(getuid());
  bool dir = access(rt.c_str(), F_OK) == 0;
  check(active == dir || !dir, "active session matches runtime dir");

  if (!auth.polkitAvailable()) {
    Peer other; other.uid = 4242; other.pid = 2; other.startTime = 5;
    std::string why;
    check(auth.authorize(other, PeerAuth::ActionDelete, &why), "delete allowed without polkit");
    check(!auth.authorize(other, PeerAuth::ActionManage, &why), "manage denied without polkit");
  }

  if (failures) return 1;
  std::cout << "ok\n";
  return 0;
}
