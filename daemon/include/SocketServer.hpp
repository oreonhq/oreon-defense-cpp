#pragma once
#include <nlohmann/json.hpp>
#include <functional>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <unistd.h>

namespace oreon {

using json = nlohmann::json;

class SocketServer {
public:
  using Handler = std::function<json(const std::string& method, const json& params)>;

  SocketServer();
  ~SocketServer();

  void setHandler(Handler h) { handler_ = std::move(h); }
  bool start(const std::string& path);
  void stop();
  void broadcast(const json& event);
  bool running() const { return running_; }

private:
  void acceptLoop();
  void clientLoop(int fd);
  void sendLine(int fd, const json& j);

  std::string path_;
  Handler handler_;
  std::thread thr_;
  std::atomic<bool> running_{false};
  int listenFd_{-1};
  std::mutex clientsMu_;
  std::vector<int> clients_;
};

} // namespace oreon
