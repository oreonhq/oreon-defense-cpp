#pragma once
#include "RuleEngine.hpp"
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <cstdint>

namespace oreon {

class RuleUpdater {
public:
  struct Status {
    std::string url;
    int64_t version{0};
    std::string published;
    int64_t lastCheck{0};
    int64_t lastUpdate{0};
    std::string lastResult;
    std::string lastError;
    bool running{false};
    bool keyPresent{false};
  };
  using RulesCb = std::function<void(const RuleSet& rs)>;
  using DoneCb = std::function<void(const Status& st, bool changed)>;

  ~RuleUpdater();
  void configure(const std::string& baseUrl, const std::string& publicKeyPath,
                 const std::string& feedDir);
  void setRulesCallback(RulesCb cb) { rulesCb_ = std::move(cb); }
  void setDoneCallback(DoneCb cb) { doneCb_ = std::move(cb); }

  bool loadStored(RuleSet& out);
  bool startAsync(bool force);
  bool updateNow(bool force, std::string* err = nullptr);
  Status status() const;
  void join();

private:
  bool fetch(const std::string& url, std::string& out, size_t maxBytes, std::string* err);
  void saveState();
  void loadState();
  bool verifyBlob(const std::string& yaml, const std::string& sig, std::string* err) const;

  std::string baseUrl_;
  std::string keyPath_;
  std::string feedDir_;
  std::string keyPem_;
  RulesCb rulesCb_;
  DoneCb doneCb_;
  mutable std::mutex mu_;
  Status st_;
  std::thread thr_;
  std::atomic<bool> running_{false};
};

}
