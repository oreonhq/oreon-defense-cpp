#include "PeerAuth.hpp"
#include <oreon/Types.hpp>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <vector>

namespace oreon {

static std::string findPkcheck() {
  for (const char* p : {"/usr/bin/pkcheck", "/bin/pkcheck"})
    if (access(p, X_OK) == 0) return p;
  return {};
}

bool PeerAuth::polkitAvailable() const {
  return !(pkcheck_.empty() ? findPkcheck() : pkcheck_).empty();
}

bool PeerAuth::isOwnerOrRoot(const Peer& peer) const {
  return peer.uid == 0 || peer.uid == geteuid();
}

bool PeerAuth::isActiveLocalSession(const Peer& peer) const {
  if (peer.pid <= 0) return false;
  if (peer.uid == static_cast<uid_t>(-1)) return false;
  struct stat st{};
  std::string rt = "/run/user/" + std::to_string(peer.uid);
  if (stat(rt.c_str(), &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == peer.uid)
    return true;
  return false;
}

bool PeerAuth::inAdminGroup(uid_t uid) const {
  passwd pw{}, *res = nullptr;
  std::vector<char> buf(16384);
  if (getpwuid_r(uid, &pw, buf.data(), buf.size(), &res) != 0 || !res) return false;
  int ngroups = 256;
  std::vector<gid_t> gids(static_cast<size_t>(ngroups));
  if (getgrouplist(pw.pw_name, pw.pw_gid, gids.data(), &ngroups) < 0) return false;
  gids.resize(static_cast<size_t>(ngroups));
  for (const auto& name : groups_) {
    group gr{}, *gres = nullptr;
    std::vector<char> gbuf(16384);
    if (getgrnam_r(name.c_str(), &gr, gbuf.data(), gbuf.size(), &gres) != 0 || !gres) continue;
    for (gid_t g : gids)
      if (g == gr.gr_gid) return true;
  }
  return false;
}

int PeerAuth::runPkcheck(const Peer& peer, const std::string& action) const {
  std::string pk = pkcheck_.empty() ? findPkcheck() : pkcheck_;
  if (pk.empty()) return -1;
  std::string proc = std::to_string(peer.pid) + "," + std::to_string(peer.startTime) + "," +
                     std::to_string(peer.uid);
  pid_t pid = fork();
  if (pid < 0) return -1;
  if (pid == 0) {
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      dup2(devnull, 0);
      dup2(devnull, 1);
      dup2(devnull, 2);
    }
    const char* argv[] = {pk.c_str(), "--action-id", action.c_str(), "--process", proc.c_str(),
                          interactive_ ? "--allow-user-interaction" : nullptr, nullptr};
    const char* envp[] = {"PATH=/usr/bin:/bin", "LC_ALL=C", nullptr};
    execve(pk.c_str(), const_cast<char* const*>(argv), const_cast<char* const*>(envp));
    _exit(127);
  }
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
  if (!WIFEXITED(status)) return 1;
  int rc = WEXITSTATUS(status);
  return rc == 127 ? -1 : rc;
}

bool PeerAuth::authorize(const Peer& peer, const std::string& action, std::string* why) {
  if (peer.pid <= 0) {
    if (why) *why = "unknown peer";
    return false;
  }
  if (isOwnerOrRoot(peer)) return true;

  const std::string key = std::to_string(peer.pid) + ":" + std::to_string(peer.startTime) + ":" + action;
  {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = cache_.find(key);
    if (it != cache_.end() && it->second > nowEpoch()) return true;
  }
  int rc = runPkcheck(peer, action);
  if (rc == 0) {
    std::lock_guard<std::mutex> lock(mu_);
    if (cache_.size() > 512) cache_.clear();
    cache_[key] = nowEpoch() + 300;
    return true;
  }
  if (rc < 0) {
    if (inAdminGroup(peer.uid)) return true;
    if (action == ActionQuarantine || action == ActionDelete) return true;
    if (why) *why = "not authorized: needs root or an admin group member";
    return false;
  }
  if (why) *why = "not authorized by polkit (" + action + ")";
  return false;
}

}
