#pragma once
#include "SocketServer.hpp"
#include <string>
#include <vector>
#include <mutex>
#include <map>

namespace oreon {

class PeerAuth {
public:
  static constexpr const char* ActionManage = "org.oreon.defense.manage";
  static constexpr const char* ActionQuarantine = "org.oreon.defense.quarantine";
  static constexpr const char* ActionNetwork = "org.oreon.defense.network";
  static constexpr const char* ActionDelete = "org.oreon.defense.delete";

  void setAdminGroups(const std::vector<std::string>& g) { groups_ = g; }
  void setPkcheckPath(const std::string& p) { pkcheck_ = p; }
  void setInteractive(bool v) { interactive_ = v; }

  bool authorize(const Peer& peer, const std::string& action, std::string* why = nullptr);
  bool isOwnerOrRoot(const Peer& peer) const;
  bool isActiveLocalSession(const Peer& peer) const;
  bool inAdminGroup(uid_t uid) const;
  bool polkitAvailable() const;

private:
  int runPkcheck(const Peer& peer, const std::string& action) const;

  std::vector<std::string> groups_{"wheel"};
  std::string pkcheck_;
  bool interactive_{true};
  std::mutex mu_;
  std::map<std::string, int64_t> cache_;
};

}
