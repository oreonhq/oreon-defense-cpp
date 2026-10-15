#include "SocketServer.hpp"
#include <oreon/Paths.hpp>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <filesystem>
#include <fstream>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <poll.h>

namespace oreon {
namespace fs = std::filesystem;

SocketServer::SocketServer() = default;

SocketServer::~SocketServer() { stop(); }

bool SocketServer::start(const std::string& path) {
  if (running_) return true;
  path_ = path;
  ensureDir(fs::path(path).parent_path().string());
  unlink(path.c_str());

  listenFd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listenFd_ < 0) return false;

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.size() >= sizeof(addr.sun_path)) {
    close(listenFd_);
    listenFd_ = -1;
    return false;
  }
  strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
  if (bind(listenFd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    close(listenFd_);
    listenFd_ = -1;
    return false;
  }
  chmod(path.c_str(), 0666);
  {
    const auto parent = fs::path(path).parent_path();
    if (!parent.empty() && isRoot())
      chmod(parent.c_str(), 0755);
  }
  if (listen(listenFd_, 32) < 0) {
    close(listenFd_);
    listenFd_ = -1;
    return false;
  }
  running_ = true;
  thr_ = std::thread([this] { acceptLoop(); });
  return true;
}

void SocketServer::stop() {
  if (!running_) return;
  running_ = false;
  if (listenFd_ >= 0) {
    shutdown(listenFd_, SHUT_RDWR);
    close(listenFd_);
    listenFd_ = -1;
  }
  {
    std::lock_guard<std::mutex> lock(clientsMu_);
    for (int c : clients_) shutdown(c, SHUT_RDWR);
  }
  if (thr_.joinable()) thr_.join();
  for (int i = 0; i < 50 && active_ > 0; ++i) usleep(20000);
  unlink(path_.c_str());
}

bool SocketServer::sendLine(int fd, const json& j) {
  std::string line = j.dump(-1, ' ', false, json::error_handler_t::replace) + "\n";
  std::lock_guard<std::mutex> lock(writeMu_);
  const char* p = line.data();
  size_t left = line.size();
  while (left > 0) {
    ssize_t n = send(fd, p, left, MSG_NOSIGNAL);
    if (n <= 0) {
      if (n < 0 && errno == EINTR) continue;
      return false;
    }
    p += n;
    left -= static_cast<size_t>(n);
  }
  return true;
}

void SocketServer::broadcast(const json& event) {
  std::vector<int> cs;
  {
    std::lock_guard<std::mutex> lock(clientsMu_);
    cs = clients_;
  }
  for (int c : cs) {
    if (!sendLine(c, event)) shutdown(c, SHUT_RDWR);
  }
}

static uint64_t procStartTime(pid_t pid) {
  std::ifstream in("/proc/" + std::to_string(pid) + "/stat");
  std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  auto rp = s.rfind(')');
  if (rp == std::string::npos) return 0;
  std::string rest = s.substr(rp + 2);
  size_t pos = 0;
  for (int field = 3; field < 22; ++field) {
    pos = rest.find(' ', pos);
    if (pos == std::string::npos) return 0;
    ++pos;
  }
  return std::strtoull(rest.c_str() + pos, nullptr, 10);
}

void SocketServer::acceptLoop() {
  while (running_) {
    int c = accept4(listenFd_, nullptr, nullptr, SOCK_CLOEXEC);
    if (c < 0) {
      if (!running_) break;
      if (errno == EMFILE || errno == ENFILE) usleep(100000);
      continue;
    }
    if (static_cast<size_t>(active_.load()) >= kMaxClients) {
      close(c);
      continue;
    }
    Peer peer;
    ucred cred{};
    socklen_t len = sizeof(cred);
    if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0) {
      peer.pid = cred.pid;
      peer.uid = cred.uid;
      peer.gid = cred.gid;
      peer.startTime = procStartTime(cred.pid);
    }
    peer.fd = c;
    timeval tv{5, 0};
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    {
      std::lock_guard<std::mutex> lock(clientsMu_);
      clients_.push_back(c);
    }
    ++active_;
    std::thread([this, c, peer] { clientLoop(c, peer); }).detach();
  }
}

void SocketServer::clientLoop(int fd, Peer peer) {
  std::string buf;
  char tmp[8192];
  while (running_) {
    ssize_t n = read(fd, tmp, sizeof(tmp));
    if (n <= 0) break;
    buf.append(tmp, static_cast<size_t>(n));
    if (buf.size() > kMaxLine && buf.find('\n') == std::string::npos) {
      sendLine(fd, json{{"ok", false}, {"error", "request too large"}});
      break;
    }
    size_t pos;
    while ((pos = buf.find('\n')) != std::string::npos) {
      std::string line = buf.substr(0, pos);
      buf.erase(0, pos + 1);
      if (line.empty()) continue;
      json req;
      try {
        req = json::parse(line);
      } catch (...) {
        sendLine(fd, json{{"ok", false}, {"error", "bad json"}});
        continue;
      }
      if (!req.is_object()) {
        sendLine(fd, json{{"ok", false}, {"error", "request must be an object"}});
        continue;
      }
      json id = req.contains("id") && (req["id"].is_string() || req["id"].is_number())
                  ? req["id"] : json("");
      if (!req.contains("method") || !req["method"].is_string()) {
        sendLine(fd, json{{"id", id}, {"ok", false}, {"error", "method must be a string"}});
        continue;
      }
      std::string method = req["method"].get<std::string>();
      json params = req.contains("params") ? req["params"] : json::object();
      if (params.is_null()) params = json::object();
      if (!params.is_object()) {
        sendLine(fd, json{{"id", id}, {"ok", false}, {"error", "params must be an object"}});
        continue;
      }
      json result;
      bool ok = true;
      std::string error;
      try {
        if (handler_) result = handler_(peer, method, params);
        else {
          ok = false;
          error = "no handler";
        }
        if (result.is_object() && result.contains("_error")) {
          ok = false;
          error = result["_error"].is_string() ? result["_error"].get<std::string>() : "error";
          json extra = result.contains("_code") ? result["_code"] : json();
          result = json::object();
          if (!extra.is_null()) result["code"] = extra;
        }
      } catch (const std::exception& e) {
        ok = false;
        error = std::string("invalid request: ") + e.what();
      }
      json resp{{"id", id}, {"ok", ok}};
      if (ok) resp["result"] = result;
      else {
        resp["error"] = error;
        if (result.contains("code")) resp["code"] = result["code"];
      }
      sendLine(fd, resp);
    }
  }
  {
    std::lock_guard<std::mutex> lock(clientsMu_);
    clients_.erase(std::remove(clients_.begin(), clients_.end(), fd), clients_.end());
  }
  close(fd);
  --active_;
}

} // namespace oreon
