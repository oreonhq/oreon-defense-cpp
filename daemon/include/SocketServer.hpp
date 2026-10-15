#pragma once
#include <nlohmann/json.hpp>
#include <functional>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <unistd.h>
#include <sys/types.h>

namespace oreon {

using json = nlohmann::json;

struct Peer {
  pid_t pid{0};
  uid_t uid{static_cast<uid_t>(-1)};
  gid_t gid{static_cast<gid_t>(-1)};
  uint64_t startTime{0};
  int fd{-1};
};

class SocketServer {
public:
  using Handler = std::function<json(const Peer& peer, const std::string& method, const json& params)>;

  static constexpr size_t kMaxLine = 1024 * 1024;
  static constexpr size_t kMaxClients = 64;

  SocketServer();
  ~SocketServer();

  void setHandler(Handler h) { handler_ = std::move(h); }
  bool start(const std::string& path);
  void stop();
  void broadcast(const json& event);
  bool running() const { return running_; }

private:
  void acceptLoop();
  void clientLoop(int fd, Peer peer);
  bool sendLine(int fd, const json& j);

  std::string path_;
  Handler handler_;
  std::thread thr_;
  std::atomic<bool> running_{false};
  std::atomic<int> active_{0};
  int listenFd_{-1};
  std::mutex clientsMu_;
  std::vector<int> clients_;
  std::mutex writeMu_;
};

} // namespace oreon
