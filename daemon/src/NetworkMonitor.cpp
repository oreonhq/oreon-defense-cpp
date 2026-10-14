#include "NetworkMonitor.hpp"
#include <fstream>
#include <sstream>
#include <cstdio>
#include <array>
#include <memory>
#include <algorithm>
#include <unistd.h>
#include <dirent.h>
#include <chrono>
#include <thread>
#include <cstring>

namespace oreon {

bool NetworkMonitor::start() {
  if (running_) return true;
  running_ = true;
  thr_ = std::thread([this] { loop(); });
  return true;
}

void NetworkMonitor::stop() {
  if (!running_) return;
  running_ = false;
  if (thr_.joinable()) thr_.join();
}

void NetworkMonitor::loop() {
  while (running_) {
    auto snap = poll();
    {
      std::lock_guard<std::mutex> lock(mu_);
      last_ = snap;
    }
    for (const auto& e : snap) {
      std::string key = e.proto + "|" + e.localAddr + "|" + e.remoteAddr + "|" + std::to_string(e.pid);
      bool isNew = false;
      {
        std::lock_guard<std::mutex> lock(mu_);
        if (seenKeys_.find(key) == seenKeys_.end()) {
          seenKeys_.insert(key);
          isNew = true;
        }
      }
      if (isNew && e.state != "LISTEN" && !e.remoteAddr.empty() && e.remoteAddr != "0.0.0.0:0" &&
          e.remoteAddr.find("127.0.0.1") == std::string::npos && cb_) {
        cb_(e);
      }
    }
    for (int i = 0; i < intervalMs_ / 100 && running_; ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

std::vector<NetworkEntry> NetworkMonitor::snapshot() const {
  std::lock_guard<std::mutex> lock(mu_);
  return last_;
}

std::string NetworkMonitor::riskHint(const NetworkEntry& e) {
  if (e.state == "LISTEN") {
    // high ports or unusual
    auto colon = e.localAddr.rfind(':');
    int port = 0;
    if (colon != std::string::npos) port = atoi(e.localAddr.c_str() + colon + 1);
    if (port == 4444 || port == 31337 || port == 5555 || port == 1337) return "high";
    if (port > 49152) return "watch";
    return "ok";
  }
  if (e.remoteAddr.find(":4444") != std::string::npos ||
      e.remoteAddr.find(":1337") != std::string::npos) return "high";
  return "ok";
}

static std::string inodeToProcess(const std::string& inode) {
  DIR* d = opendir("/proc");
  if (!d) return {};
  dirent* ent;
  while ((ent = readdir(d)) != nullptr) {
    if (ent->d_name[0] < '1' || ent->d_name[0] > '9') continue;
    std::string fdpath = std::string("/proc/") + ent->d_name + "/fd";
    DIR* fd = opendir(fdpath.c_str());
    if (!fd) continue;
    dirent* fde;
    while ((fde = readdir(fd)) != nullptr) {
      char link[256];
      std::string full = fdpath + "/" + fde->d_name;
      ssize_t n = readlink(full.c_str(), link, sizeof(link) - 1);
      if (n <= 0) continue;
      link[n] = 0;
      std::string target(link);
      if (target.find("socket:[" + inode + "]") != std::string::npos) {
        closedir(fd);
        closedir(d);
        std::ifstream comm(std::string("/proc/") + ent->d_name + "/comm");
        std::string name;
        std::getline(comm, name);
        return std::string(ent->d_name) + ":" + name;
      }
    }
    closedir(fd);
  }
  closedir(d);
  return {};
}

static std::string hexIpPort(const std::string& hex) {
  // local_address format: AABBCCDD:PPPP
  auto colon = hex.find(':');
  if (colon == std::string::npos) return hex;
  unsigned ip = 0, port = 0;
  sscanf(hex.substr(0, colon).c_str(), "%X", &ip);
  sscanf(hex.substr(colon + 1).c_str(), "%X", &port);
  char buf[64];
  snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u",
           ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff, port);
  return buf;
}

std::vector<NetworkEntry> NetworkMonitor::poll() {
  std::vector<NetworkEntry> out;

  auto parse = [&](const std::string& path, const std::string& proto) {
    std::ifstream in(path);
    std::string line;
    std::getline(in, line); // header
    while (std::getline(in, line)) {
      std::istringstream iss(line);
      std::string sl, local, rem, state, skip, inode;
      int dummy;
      iss >> sl >> local >> rem >> state;
      for (int i = 0; i < 5; ++i) iss >> skip;
      iss >> inode;
      NetworkEntry e;
      e.proto = proto;
      e.localAddr = hexIpPort(local);
      e.remoteAddr = hexIpPort(rem);
      // tcp states
      if (state == "0A") e.state = "LISTEN";
      else if (state == "01") e.state = "ESTABLISHED";
      else if (state == "06") e.state = "TIME_WAIT";
      else e.state = state;
      auto proc = inodeToProcess(inode);
      if (!proc.empty()) {
        auto c = proc.find(':');
        e.pid = atoi(proc.c_str());
        e.process = c != std::string::npos ? proc.substr(c + 1) : "";
      }
      e.risk = riskHint(e);
      if (e.state == "LISTEN" || e.state == "ESTABLISHED")
        out.push_back(e);
    }
  };

  parse("/proc/net/tcp", "tcp");
  parse("/proc/net/tcp6", "tcp6");
  // cap size
  if (out.size() > 200) out.resize(200);
  return out;
}

} // namespace oreon
