#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <map>
#include <set>
#include <cstdint>
#include <atomic>

namespace oreon {

class NetBlocker {
public:
  struct Entry {
    std::string cidr;
    std::string reason;
    std::string source;
    int64_t added{0};
  };

  static bool normalize(const std::string& in, std::string& out, bool& v6, std::string* err);
  static std::string tableName() { return "oreon_defense"; }

  void setStatePath(const std::string& p) { statePath_ = p; }
  void setNftPath(const std::string& p) { nft_ = p; }
  void loadState();

  void setFeed(const std::vector<std::pair<std::string, std::string>>& entries);
  bool block(const std::string& addr, const std::string& reason, std::string* err);
  bool unblock(const std::string& addr, std::string* err);
  std::vector<Entry> list() const;
  bool isBlocked(const std::string& ip) const;

  bool enable(std::string* err);
  void disable();
  bool active() const { return active_; }
  bool available() const;
  std::string lastError() const;

private:
  bool apply(std::string* err);
  bool runNft(const std::string& script, std::string* err) const;
  void saveState() const;
  std::string buildScript() const;

  mutable std::mutex mu_;
  std::string statePath_;
  std::string nft_;
  std::map<std::string, Entry> feed_;
  std::map<std::string, Entry> user_;
  std::set<std::string> unblocked_;
  std::atomic<bool> active_{false};
  std::string lastError_;
};

}
