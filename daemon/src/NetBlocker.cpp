#include "NetBlocker.hpp"
#include "Signature.hpp"
#include <oreon/Types.hpp>
#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <csignal>
#include <cstring>
#include <sstream>
#include <filesystem>

namespace oreon {
namespace fs = std::filesystem;
using json = nlohmann::json;

static std::string findNft() {
  for (const char* p : {"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"})
    if (access(p, X_OK) == 0) return p;
  return {};
}

bool NetBlocker::available() const {
  return !(nft_.empty() ? findNft() : nft_).empty();
}

std::string NetBlocker::lastError() const {
  std::lock_guard<std::mutex> lock(mu_);
  return lastError_;
}

bool NetBlocker::normalize(const std::string& in, std::string& out, bool& v6, std::string* err) {
  auto fail = [&](const std::string& m) {
    if (err) *err = m;
    return false;
  };
  if (in.empty() || in.size() > 64) return fail("bad address");
  for (char c : in)
    if (!(isxdigit(static_cast<unsigned char>(c)) || c == '.' || c == ':' || c == '/'))
      return fail("bad address characters");
  std::string addr = in;
  int prefix = -1;
  auto slash = in.find('/');
  if (slash != std::string::npos) {
    addr = in.substr(0, slash);
    std::string p = in.substr(slash + 1);
    if (p.empty() || p.size() > 3 || p.find_first_not_of("0123456789") != std::string::npos)
      return fail("bad prefix");
    prefix = std::stoi(p);
  }
  unsigned char buf[16] = {0};
  char text[INET6_ADDRSTRLEN] = {0};
  if (inet_pton(AF_INET, addr.c_str(), buf) == 1) {
    v6 = false;
    if (prefix < 0) prefix = 32;
    if (prefix > 32) return fail("bad prefix");
    if (prefix < 8) return fail("range too wide");
    uint32_t a = (uint32_t(buf[0]) << 24) | (uint32_t(buf[1]) << 16) | (uint32_t(buf[2]) << 8) | buf[3];
    uint32_t mask = prefix == 0 ? 0 : 0xffffffffu << (32 - prefix);
    a &= mask;
    if ((a >> 24) == 127 || (a >> 24) == 0) return fail("refusing loopback or unspecified address");
    if ((a >> 28) == 0xE) return fail("refusing multicast address");
    if (a == 0xffffffffu) return fail("refusing broadcast address");
    buf[0] = a >> 24; buf[1] = (a >> 16) & 0xff; buf[2] = (a >> 8) & 0xff; buf[3] = a & 0xff;
    inet_ntop(AF_INET, buf, text, sizeof(text));
    out = text;
    if (prefix != 32) out += "/" + std::to_string(prefix);
    return true;
  }
  if (inet_pton(AF_INET6, addr.c_str(), buf) == 1) {
    v6 = true;
    if (prefix < 0) prefix = 128;
    if (prefix > 128) return fail("bad prefix");
    if (prefix < 16) return fail("range too wide");
    for (int i = 0; i < 16; ++i) {
      int bits = prefix - i * 8;
      if (bits >= 8) continue;
      if (bits <= 0) buf[i] = 0;
      else buf[i] &= static_cast<unsigned char>(0xff << (8 - bits));
    }
    static const unsigned char loop[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    static const unsigned char zero[16] = {0};
    if (memcmp(buf, loop, 16) == 0 || memcmp(buf, zero, 16) == 0)
      return fail("refusing loopback or unspecified address");
    if (buf[0] == 0xff) return fail("refusing multicast address");
    if (buf[0] == 0xfe && (buf[1] & 0xc0) == 0x80) return fail("refusing link-local range");
    inet_ntop(AF_INET6, buf, text, sizeof(text));
    out = text;
    if (prefix != 128) out += "/" + std::to_string(prefix);
    return true;
  }
  return fail("not an IP address");
}

void NetBlocker::loadState() {
  std::lock_guard<std::mutex> lock(mu_);
  std::string text;
  if (statePath_.empty() || !readWholeFile(statePath_, text, 4 * 1024 * 1024)) return;
  try {
    auto j = json::parse(text);
    for (const auto& e : j.value("user", json::array())) {
      std::string n, err;
      bool v6;
      if (!normalize(e.value("cidr", ""), n, v6, &err)) continue;
      user_[n] = Entry{n, e.value("reason", ""), "user", e.value("added", int64_t{0})};
    }
    for (const auto& e : j.value("unblocked", json::array()))
      if (e.is_string()) unblocked_.insert(e.get<std::string>());
  } catch (...) {}
}

void NetBlocker::saveState() const {
  if (statePath_.empty()) return;
  json users = json::array();
  for (const auto& [k, e] : user_)
    users.push_back({{"cidr", e.cidr}, {"reason", e.reason}, {"added", e.added}});
  json j{{"user", users}, {"unblocked", std::vector<std::string>(unblocked_.begin(), unblocked_.end())}};
  writeFileAtomic(statePath_, j.dump(2) + "\n", 0600);
}

void NetBlocker::setFeed(const std::vector<std::pair<std::string, std::string>>& entries) {
  {
    std::lock_guard<std::mutex> lock(mu_);
    feed_.clear();
    for (const auto& [addr, reason] : entries) {
      std::string n, err;
      bool v6;
      if (!normalize(addr, n, v6, &err)) continue;
      feed_[n] = Entry{n, reason, "feed", nowEpoch()};
    }
  }
  if (active_) apply(nullptr);
}

bool NetBlocker::block(const std::string& addr, const std::string& reason, std::string* err) {
  std::string n;
  bool v6;
  if (!normalize(addr, n, v6, err)) return false;
  {
    std::lock_guard<std::mutex> lock(mu_);
    user_[n] = Entry{n, reason.substr(0, 200), "user", nowEpoch()};
    unblocked_.erase(n);
    saveState();
  }
  return active_ ? apply(err) : true;
}

bool NetBlocker::unblock(const std::string& addr, std::string* err) {
  std::string n;
  bool v6;
  if (!normalize(addr, n, v6, err)) return false;
  {
    std::lock_guard<std::mutex> lock(mu_);
    bool found = user_.erase(n) > 0;
    if (feed_.count(n)) {
      unblocked_.insert(n);
      found = true;
    }
    if (!found) {
      if (err) *err = "not blocked";
      return false;
    }
    saveState();
  }
  return active_ ? apply(err) : true;
}

std::vector<NetBlocker::Entry> NetBlocker::list() const {
  std::lock_guard<std::mutex> lock(mu_);
  std::vector<Entry> out;
  for (const auto& [k, e] : feed_)
    if (!unblocked_.count(k) && !user_.count(k)) out.push_back(e);
  for (const auto& [k, e] : user_) out.push_back(e);
  return out;
}

static bool inCidr(const std::string& ip, const std::string& cidr) {
  unsigned char a[16], b[16];
  std::string net = cidr;
  int prefix = -1;
  auto s = cidr.find('/');
  if (s != std::string::npos) {
    net = cidr.substr(0, s);
    prefix = std::stoi(cidr.substr(s + 1));
  }
  int fam = ip.find(':') != std::string::npos ? AF_INET6 : AF_INET;
  if (inet_pton(fam, ip.c_str(), a) != 1 || inet_pton(fam, net.c_str(), b) != 1) return false;
  int len = fam == AF_INET ? 4 : 16;
  if (prefix < 0) prefix = len * 8;
  for (int i = 0; i < len; ++i) {
    int bits = prefix - i * 8;
    if (bits <= 0) break;
    unsigned char m = bits >= 8 ? 0xff : static_cast<unsigned char>(0xff << (8 - bits));
    if ((a[i] & m) != (b[i] & m)) return false;
  }
  return true;
}

bool NetBlocker::isBlocked(const std::string& ip) const {
  for (const auto& e : list())
    if (inCidr(ip, e.cidr)) return true;
  return false;
}

std::string NetBlocker::buildScript() const {
  std::vector<std::string> v4, v6;
  auto add = [&](const std::string& c) {
    (c.find(':') != std::string::npos ? v6 : v4).push_back(c);
  };
  for (const auto& [k, e] : feed_)
    if (!unblocked_.count(k) && !user_.count(k)) add(k);
  for (const auto& [k, e] : user_) add(k);

  auto join = [](const std::vector<std::string>& v) {
    std::string s;
    for (size_t i = 0; i < v.size(); ++i) {
      if (i) s += ", ";
      s += v[i];
    }
    return s;
  };
  const std::string t = tableName();
  std::ostringstream o;
  o << "add table inet " << t << "\n";
  o << "delete table inet " << t << "\n";
  o << "table inet " << t << " {\n";
  o << "  set blocklist4 {\n    type ipv4_addr\n    flags interval\n    auto-merge\n";
  if (!v4.empty()) o << "    elements = { " << join(v4) << " }\n";
  o << "  }\n";
  o << "  set blocklist6 {\n    type ipv6_addr\n    flags interval\n    auto-merge\n";
  if (!v6.empty()) o << "    elements = { " << join(v6) << " }\n";
  o << "  }\n";
  o << "  chain output {\n    type filter hook output priority filter - 10; policy accept;\n"
       "    ip daddr @blocklist4 counter reject\n"
       "    ip6 daddr @blocklist6 counter reject\n  }\n";
  o << "  chain input {\n    type filter hook input priority filter - 10; policy accept;\n"
       "    ip saddr @blocklist4 counter drop\n"
       "    ip6 saddr @blocklist6 counter drop\n  }\n";
  o << "  chain forward {\n    type filter hook forward priority filter - 10; policy accept;\n"
       "    ip daddr @blocklist4 counter reject\n"
       "    ip6 daddr @blocklist6 counter reject\n  }\n";
  o << "}\n";
  return o.str();
}

bool NetBlocker::runNft(const std::string& script, std::string* err) const {
  std::string nft = nft_.empty() ? findNft() : nft_;
  if (nft.empty()) {
    if (err) *err = "nft not found (install nftables)";
    return false;
  }
  int in[2], outp[2];
  if (pipe2(in, O_CLOEXEC) != 0) return false;
  if (pipe2(outp, O_CLOEXEC) != 0) {
    close(in[0]); close(in[1]);
    return false;
  }
  pid_t pid = fork();
  if (pid < 0) {
    close(in[0]); close(in[1]); close(outp[0]); close(outp[1]);
    if (err) *err = "fork failed";
    return false;
  }
  if (pid == 0) {
    dup2(in[0], 0);
    dup2(outp[1], 1);
    dup2(outp[1], 2);
    const char* argv[] = {nft.c_str(), "-f", "-", nullptr};
    const char* envp[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", nullptr};
    execve(nft.c_str(), const_cast<char* const*>(argv), const_cast<char* const*>(envp));
    _exit(127);
  }
  close(in[0]);
  close(outp[1]);
  signal(SIGPIPE, SIG_IGN);
  const char* p = script.data();
  size_t left = script.size();
  while (left > 0) {
    ssize_t n = write(in[1], p, left);
    if (n <= 0) break;
    p += n;
    left -= static_cast<size_t>(n);
  }
  close(in[1]);
  std::string output;
  char buf[1024];
  for (;;) {
    pollfd pfd{outp[0], POLLIN, 0};
    if (poll(&pfd, 1, 10000) <= 0) break;
    ssize_t n = read(outp[0], buf, sizeof(buf));
    if (n <= 0) break;
    if (output.size() < 8192) output.append(buf, static_cast<size_t>(n));
  }
  close(outp[0]);
  int status = 0;
  waitpid(pid, &status, 0);
  bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
  if (!ok && err) *err = output.empty() ? "nft failed" : output;
  return ok;
}

bool NetBlocker::apply(std::string* err) {
  std::string script;
  {
    std::lock_guard<std::mutex> lock(mu_);
    script = buildScript();
  }
  std::string e;
  bool ok = runNft(script, &e);
  std::lock_guard<std::mutex> lock(mu_);
  lastError_ = ok ? std::string() : e;
  if (!ok && err) *err = e;
  return ok;
}

bool NetBlocker::enable(std::string* err) {
  active_ = true;
  if (!apply(err)) {
    active_ = false;
    return false;
  }
  return true;
}

void NetBlocker::disable() {
  if (!active_) return;
  active_ = false;
  std::string e;
  runNft("add table inet " + tableName() + "\ndelete table inet " + tableName() + "\n", &e);
}

}
