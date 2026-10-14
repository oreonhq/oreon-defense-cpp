#include "SocketServer.hpp"
#include <oreon/Paths.hpp>
#include <sys/socket.h>
#include <sys/un.h>
#include <filesystem>
#include <sys/stat.h>
#include <cstring>
#include <iostream>
#include <algorithm>

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
  strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
  if (bind(listenFd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    close(listenFd_);
    listenFd_ = -1;
    return false;
  }
  // world-rw so desktop users can talk to the system daemon
  chmod(path.c_str(), 0666);
  {
    const auto parent = fs::path(path).parent_path();
    if (!parent.empty())
      chmod(parent.c_str(), 0755);
  }
  if (listen(listenFd_, 16) < 0) {
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
    for (int c : clients_) close(c);
    clients_.clear();
  }
  if (thr_.joinable()) thr_.join();
  unlink(path_.c_str());
}

void SocketServer::sendLine(int fd, const json& j) {
  std::string line = j.dump() + "\n";
  const char* p = line.data();
  size_t left = line.size();
  while (left > 0) {
    ssize_t n = write(fd, p, left);
    if (n <= 0) break;
    p += n;
    left -= static_cast<size_t>(n);
  }
}

void SocketServer::broadcast(const json& event) {
  std::lock_guard<std::mutex> lock(clientsMu_);
  std::vector<int> dead;
  for (int c : clients_) {
    // peek if still ok
    sendLine(c, event);
  }
}

void SocketServer::acceptLoop() {
  while (running_) {
    int c = accept4(listenFd_, nullptr, nullptr, SOCK_CLOEXEC);
    if (c < 0) {
      if (!running_) break;
      continue;
    }
    {
      std::lock_guard<std::mutex> lock(clientsMu_);
      clients_.push_back(c);
    }
    std::thread([this, c] { clientLoop(c); }).detach();
  }
}

void SocketServer::clientLoop(int fd) {
  std::string buf;
  char tmp[4096];
  while (running_) {
    ssize_t n = read(fd, tmp, sizeof(tmp));
    if (n <= 0) break;
    buf.append(tmp, static_cast<size_t>(n));
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
      std::string id = req.value("id", "");
      std::string method = req.value("method", "");
      json params = req.value("params", json::object());
      json result;
      bool ok = true;
      std::string error;
      try {
        if (handler_) result = handler_(method, params);
        else {
          ok = false;
          error = "no handler";
        }
        if (result.contains("_error")) {
          ok = false;
          error = result["_error"].get<std::string>();
          result = json::object();
        }
      } catch (const std::exception& e) {
        ok = false;
        error = e.what();
      }
      json resp{{"id", id}, {"ok", ok}};
      if (ok) resp["result"] = result;
      else resp["error"] = error;
      sendLine(fd, resp);
    }
  }
  {
    std::lock_guard<std::mutex> lock(clientsMu_);
    clients_.erase(std::remove(clients_.begin(), clients_.end(), fd), clients_.end());
  }
  close(fd);
}

} // namespace oreon
