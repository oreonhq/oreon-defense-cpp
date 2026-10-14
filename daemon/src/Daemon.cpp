#include "Daemon.hpp"
#include <oreon/Protocol.hpp>
#include <oreon/JsonUtil.hpp>
#include <oreon/Hash.hpp>
#include <filesystem>
#include <iostream>
#include <csignal>
#include <thread>
#include <chrono>
#include <algorithm>
#include <ctime>

namespace oreon {
namespace fs = std::filesystem;

static Daemon* gDaemon = nullptr;

static void onSignal(int) {
  if (gDaemon) gDaemon->requestStop();
}

bool Daemon::init(const std::string& configPath) {
  gDaemon = this;
  std::signal(SIGINT, onSignal);
  std::signal(SIGTERM, onSignal);

  if (!config_.load(configPath)) return false;
  auto& cfg = config_.get();

  log_.open(cfg.logPath);
  quarantine_.setDir(cfg.quarantineDir);
  quarantine_.reload();

  // seed rules: copy bundled if missing
  if (!fs::exists(cfg.rulesPath)) {
    const char* candidates[] = {
      "/usr/share/oreon-defense/rules/starter-rules.yaml",
      "data/rules/starter-rules.yaml",
      "../data/rules/starter-rules.yaml",
      "../../data/rules/starter-rules.yaml"
    };
    for (auto c : candidates) {
      if (fs::exists(c)) {
        ensureDir(fs::path(cfg.rulesPath).parent_path().string());
        std::error_code ec;
        fs::copy_file(c, cfg.rulesPath, fs::copy_options::overwrite_existing, ec);
        break;
      }
    }
  }
  if (!engine_.loadFile(cfg.rulesPath)) {
    log_.warn("system", "failed to load rules, using empty set", cfg.rulesPath);
  } else {
    log_.info("system", "loaded " + std::to_string(engine_.ruleCount()) + " rules", cfg.rulesPath);
  }

  // Always keep our own state out of watches/scans (config may omit these).
  auto ensureExcl = [&](const std::string& p) {
    if (p.empty()) return;
    auto& ex = cfg.exclusions;
    if (std::find(ex.begin(), ex.end(), p) == ex.end()) ex.push_back(p);
  };
  ensureExcl(cfg.dataDir);
  ensureExcl(cfg.quarantineDir);
  ensureExcl("/var/lib/oreon-defense");

  scanner_.setRuleEngine(&engine_);
  scanner_.setQuarantine(&quarantine_);
  scanner_.setEventLog(&log_);
  scanner_.setExclusions(cfg.exclusions);
  scanner_.setAutoQuarantine(true);
  scanner_.setProgressCb([this](const ScanProgress& p) {
    json j{
      {"event", proto::EventScanProgress},
      {"data", {
        {"scanId", p.scanId},
        {"type", p.type},
        {"filesScanned", p.filesScanned},
        {"filesTotal", p.filesTotal},
        {"threatsFound", p.threatsFound},
        {"currentPath", p.currentPath},
        {"running", p.running},
        {"cancelled", p.cancelled}
      }}
    };
    server_.broadcast(j);
    if (!p.running) {
      status_.lastScan = nowEpoch();
      refreshStatus();
      server_.broadcast(json{{"event", proto::EventScanDone}, {"data", j["data"]}});
    }
  });
  scanner_.setThreatCb([this](const Threat& t) { onThreat(t, false); });

  fileMon_.setPaths(cfg.watchPaths);
  fileMon_.setExclusions(cfg.exclusions);
  fileMon_.setCallback([this](const FileEvent& e) { onFileEvent(e); });

  procMon_.setIntervalMs(cfg.processPollMs);
  procMon_.setRuleEngine(&engine_);
  procMon_.setCallback([this](const ProcessEvent& e) { onProcessEvent(e); });

  netMon_.setIntervalMs(cfg.networkPollMs);
  netMon_.setCallback([this](const NetworkEntry& e) { onNetworkEvent(e); });

  server_.setHandler([this](const std::string& m, const json& p) { return handleRequest(m, p); });
  if (!server_.start(cfg.socketPath)) {
    std::cerr << "failed to bind socket " << cfg.socketPath << "\n";
    return false;
  }

  log_.addListener([this](const LogEvent& e) {
    server_.broadcast(json{{"event", proto::EventLog}, {"data", logToJson(e)}});
  });

  status_.fileRealtime = cfg.fileRealtime;
  status_.processWatch = cfg.processWatch;
  status_.networkWatch = cfg.networkWatch;
  refreshStatus();
  applyProtection();

  log_.info("system", "daemon ready");
  return true;
}

void Daemon::applyProtection() {
  auto& cfg = config_.get();
  if (cfg.fileRealtime && status_.fileRealtime) {
    if (!fileMon_.running()) fileMon_.start();
  } else {
    fileMon_.stop();
  }
  if (cfg.processWatch && status_.processWatch) {
    if (!procMon_.running()) procMon_.start();
  } else {
    procMon_.stop();
  }
  if (cfg.networkWatch && status_.networkWatch) {
    if (!netMon_.running()) netMon_.start();
  } else {
    netMon_.stop();
  }
}

void Daemon::refreshStatus() {
  std::lock_guard<std::mutex> lock(mu_);
  status_.quarantineCount = quarantine_.list().size();
  uint64_t active = 0;
  for (const auto& t : threats_) {
    if (t.action == ThreatAction::Detected || t.action == ThreatAction::Blocked)
      ++active;
  }
  status_.threatCount = active;
  bool any = status_.fileRealtime || status_.processWatch || status_.networkWatch;
  status_.protectedStatus = any && active == 0;
  if (!any) status_.statusText = "Protection off";
  else if (active > 0) status_.statusText = "At risk";
  else status_.statusText = "Protected";
}

void Daemon::onFileEvent(const FileEvent& ev) {
  if (ev.op == "delete") return;
  // Never react to our own state or quarantine blobs (avoids re-quarantine loops).
  const auto& cfg = config_.get();
  if (!cfg.dataDir.empty() && (ev.path == cfg.dataDir || ev.path.find(cfg.dataDir + "/") == 0))
    return;
  if (!cfg.quarantineDir.empty() &&
      (ev.path == cfg.quarantineDir || ev.path.find(cfg.quarantineDir + "/") == 0))
    return;
  if (ev.path.find("/oreon-defense/") != std::string::npos) return;

  // Prefer CLOSE_WRITE; still accept create/modify after a short settle.
  std::this_thread::sleep_for(std::chrono::milliseconds(120));
  if (!fs::exists(ev.path) || !fs::is_regular_file(ev.path)) return;

  // Deduplicate rapid create+close bursts on the same path.
  {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = recentFileHits_.find(ev.path);
    int64_t now = nowEpoch();
    if (it != recentFileHits_.end() && now - it->second < 2) return;
    recentFileHits_[ev.path] = now;
  }

  auto m = engine_.matchFile(ev.path);
  if (!m.matched) return;

  Threat t;
  t.id = "thr-" + std::to_string(nowEpoch());
  t.name = m.rule.name;
  t.path = ev.path;
  t.ruleId = m.rule.id;
  t.description = m.rule.description + " [" + m.detail + "]";
  t.severity = m.rule.severity;
  t.sha256 = sha256File(ev.path);
  t.timestamp = nowEpoch();
  onThreat(t, true);
}

void Daemon::onProcessEvent(const ProcessEvent& ev) {
  if (!ev.suspicious) return;
  Threat t;
  t.id = "thr-proc-" + std::to_string(ev.pid) + "-" + std::to_string(nowEpoch());
  t.name = "Suspicious process: " + ev.name;
  t.path = ev.exe.empty() ? ev.cmdline : ev.exe;
  t.ruleId = "process-watch";
  t.description = ev.reason;
  t.severity = Severity::High;
  t.timestamp = nowEpoch();
  t.action = ThreatAction::Detected;
  {
    std::lock_guard<std::mutex> lock(mu_);
    threats_.push_back(t);
  }
  log_.alert("process", Severity::High, t.name + " - " + ev.reason, t.path);
  server_.broadcast(json{{"event", proto::EventThreat}, {"data", threatToJson(t)}});
  refreshStatus();
  server_.broadcast(json{{"event", proto::EventStatus}, {"data", protectionToJson(status_)}});
}

void Daemon::onNetworkEvent(const NetworkEntry& ev) {
  if (ev.risk != "high") return;
  log_.warn("network", "risky connection " + ev.process + " " + ev.remoteAddr);
  server_.broadcast(json{
    {"event", proto::EventNetwork},
    {"data", {
      {"proto", ev.proto},
      {"localAddr", ev.localAddr},
      {"remoteAddr", ev.remoteAddr},
      {"state", ev.state},
      {"pid", ev.pid},
      {"process", ev.process},
      {"risk", ev.risk}
    }}
  });
}

void Daemon::onThreat(Threat t, bool autoQuarantine) {
  if (engine_.isAllowed(t.path) || allowedPaths_.count(t.path)) {
    t.action = ThreatAction::Allowed;
    return;
  }
  // Skip if this path was already handled (detected/quarantined) moments ago.
  {
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto& existing : threats_) {
      if (existing.path == t.path &&
          (existing.action == ThreatAction::Detected ||
           existing.action == ThreatAction::Quarantined) &&
          t.timestamp - existing.timestamp < 5) {
        return;
      }
    }
  }
  if (autoQuarantine) {
    auto q = quarantine_.quarantineFile(t.path, t);
    if (q) {
      t.action = ThreatAction::Quarantined;
      t.quarantineId = q->id;
      log_.alert("threat", t.severity, "quarantined " + t.name, t.path);
    } else {
      log_.alert("threat", t.severity, "detected " + t.name, t.path);
    }
  } else {
    // Scanner already quarantined when autoQuarantine_ is on; keep action as-is.
    if (t.action == ThreatAction::Quarantined)
      log_.alert("threat", t.severity, "quarantined " + t.name, t.path);
    else
      log_.alert("threat", t.severity, "detected " + t.name, t.path);
  }
  {
    std::lock_guard<std::mutex> lock(mu_);
    threats_.push_back(t);
  }
  refreshStatus();
  server_.broadcast(json{{"event", proto::EventThreat}, {"data", threatToJson(t)}});
  server_.broadcast(json{{"event", proto::EventStatus}, {"data", protectionToJson(status_)}});
}

std::vector<std::string> Daemon::quickScanRoots() const {
  // Prefer configured watch paths so systemd (root) scans real user homes,
  // not only /root/Downloads.
  const auto& watches = config_.get().watchPaths;
  if (!watches.empty()) {
    std::vector<std::string> roots = watches;
    // Keep /tmp in the mix even if config omitted it.
    if (std::find(roots.begin(), roots.end(), "/tmp") == roots.end())
      roots.push_back("/tmp");
    return roots;
  }
  if (isRoot())
    return {"/home", "/tmp"};
  std::string home = homeDir();
  return {home + "/Downloads", home + "/Desktop", "/tmp"};
}

std::vector<std::string> Daemon::fullScanRoots() const {
  if (isRoot())
    return {"/home", "/tmp"};
  return {homeDir()};
}

json Daemon::handleRequest(const std::string& method, const json& params) {
  using namespace proto;
  if (method == MethodPing) return json{{"pong", true}, {"version", "1.0.3"}};

  if (method == MethodGetStatus) {
    refreshStatus();
    return protectionToJson(status_);
  }

  if (method == MethodSetProtection) {
    if (params.contains("fileRealtime")) status_.fileRealtime = params["fileRealtime"].get<bool>();
    if (params.contains("processWatch")) status_.processWatch = params["processWatch"].get<bool>();
    if (params.contains("networkWatch")) status_.networkWatch = params["networkWatch"].get<bool>();
    config_.get().fileRealtime = status_.fileRealtime;
    config_.get().processWatch = status_.processWatch;
    config_.get().networkWatch = status_.networkWatch;
    config_.save();
    applyProtection();
    refreshStatus();
    server_.broadcast(json{{"event", EventStatus}, {"data", protectionToJson(status_)}});
    return protectionToJson(status_);
  }

  if (method == MethodStartScan) {
    std::string type = params.value("type", "quick");
    std::vector<std::string> roots;
    if (type == "custom") {
      if (params.contains("paths")) roots = params["paths"].get<std::vector<std::string>>();
      else if (params.contains("path")) roots = {params["path"].get<std::string>()};
    } else if (type == "full") {
      roots = fullScanRoots();
    } else {
      roots = quickScanRoots();
    }
    if (roots.empty()) return json{{"_error", "no paths"}};
    if (!scanner_.start(type, roots)) return json{{"_error", "scan already running"}};
    return json{{"started", true}, {"type", type}};
  }

  if (method == MethodCancelScan) {
    scanner_.cancel();
    return json{{"cancelled", true}};
  }

  if (method == MethodGetScanProgress) {
    auto p = scanner_.progress();
    return json{
      {"scanId", p.scanId},
      {"type", p.type},
      {"filesScanned", p.filesScanned},
      {"filesTotal", p.filesTotal},
      {"threatsFound", p.threatsFound},
      {"currentPath", p.currentPath},
      {"running", p.running},
      {"cancelled", p.cancelled}
    };
  }

  if (method == MethodGetThreats) {
    std::lock_guard<std::mutex> lock(mu_);
    json arr = json::array();
    for (const auto& t : threats_) arr.push_back(threatToJson(t));
    return json{{"threats", arr}};
  }

  if (method == MethodGetQuarantine) {
    json arr = json::array();
    for (const auto& q : quarantine_.list()) arr.push_back(quarantineToJson(q));
    return json{{"items", arr}};
  }

  if (method == MethodQuarantine) {
    std::string path = params.value("path", "");
    std::string id = params.value("id", "");
    Threat t;
    {
      std::lock_guard<std::mutex> lock(mu_);
      for (auto& x : threats_) {
        if ((!id.empty() && x.id == id) || (!path.empty() && x.path == path)) {
          t = x;
          break;
        }
      }
    }
    if (t.path.empty()) t.path = path;
    if (t.name.empty()) t.name = "Manual quarantine";
    t.severity = Severity::High;
    auto q = quarantine_.quarantineFile(t.path, t);
    if (!q) return json{{"_error", "quarantine failed"}};
    {
      std::lock_guard<std::mutex> lock(mu_);
      for (auto& x : threats_) {
        if ((!id.empty() && x.id == id) || (!path.empty() && x.path == path) || x.path == t.path) {
          x.action = ThreatAction::Quarantined;
          x.quarantineId = q->id;
        }
      }
    }
    refreshStatus();
    return quarantineToJson(*q);
  }

  if (method == MethodRestore) {
    std::string id = params.value("id", "");
    std::string err;
    if (!quarantine_.restore(id, &err)) return json{{"_error", err}};
    refreshStatus();
    return json{{"restored", true}};
  }

  if (method == MethodDeleteQuarantine) {
    std::string id = params.value("id", "");
    std::string err;
    if (!quarantine_.remove(id, &err)) return json{{"_error", err}};
    refreshStatus();
    return json{{"deleted", true}};
  }

  if (method == MethodAllow) {
    std::string path = params.value("path", "");
    if (path.empty()) return json{{"_error", "path required"}};
    allowedPaths_.insert(path);
    engine_.addAllowPath(path);
    std::lock_guard<std::mutex> lock(mu_);
    threats_.erase(std::remove_if(threats_.begin(), threats_.end(),
      [&](const Threat& t) { return t.path == path; }), threats_.end());
    refreshStatus();
    return json{{"allowed", true}};
  }

  if (method == MethodGetNetwork) {
    json arr = json::array();
    for (const auto& e : netMon_.snapshot()) {
      arr.push_back({
        {"proto", e.proto},
        {"localAddr", e.localAddr},
        {"remoteAddr", e.remoteAddr},
        {"state", e.state},
        {"pid", e.pid},
        {"process", e.process},
        {"risk", e.risk}
      });
    }
    return json{{"entries", arr}};
  }

  if (method == MethodGetHistory) {
    std::string search = params.value("search", "");
    size_t limit = params.value("limit", 500);
    json arr = json::array();
    for (const auto& e : log_.query(search, limit)) arr.push_back(logToJson(e));
    return json{{"events", arr}};
  }

  if (method == MethodGetConfig) {
    const auto& c = config_.get();
    return json{
      {"watchPaths", c.watchPaths},
      {"exclusions", c.exclusions},
      {"rulesPath", c.rulesPath},
      {"scheduleHour", c.scheduleHour},
      {"scheduleMinute", c.scheduleMinute},
      {"scheduleType", c.scheduleType},
      {"fileRealtime", c.fileRealtime},
      {"processWatch", c.processWatch},
      {"networkWatch", c.networkWatch}
    };
  }

  if (method == MethodSetConfig) {
    auto& c = config_.get();
    if (params.contains("watchPaths")) c.watchPaths = params["watchPaths"].get<std::vector<std::string>>();
    if (params.contains("exclusions")) c.exclusions = params["exclusions"].get<std::vector<std::string>>();
    if (params.contains("scheduleHour")) c.scheduleHour = params["scheduleHour"].get<int>();
    if (params.contains("scheduleMinute")) c.scheduleMinute = params["scheduleMinute"].get<int>();
    if (params.contains("scheduleType")) c.scheduleType = params["scheduleType"].get<std::string>();
    config_.save();
    fileMon_.stop();
    fileMon_.setPaths(c.watchPaths);
    fileMon_.setExclusions(c.exclusions);
    scanner_.setExclusions(c.exclusions);
    applyProtection();
    return json{{"saved", true}};
  }

  if (method == MethodUpdateRules) {
    std::string path = params.value("path", config_.get().rulesPath);
    if (!engine_.loadFile(path)) return json{{"_error", "load failed"}};
    config_.get().rulesPath = path;
    config_.save();
    return json{{"rules", engine_.ruleCount()}};
  }

  return json{{"_error", "unknown method: " + method}};
}

int Daemon::run() {
  // scheduled scan loop
  while (!stop_) {
    auto& c = config_.get();
    if (c.scheduleType == "daily" && c.scheduleHour >= 0 && !scanner_.running()) {
      time_t now = time(nullptr);
      tm lt{};
      localtime_r(&now, &lt);
      if (lt.tm_hour == c.scheduleHour && lt.tm_min == c.scheduleMinute && lt.tm_sec < 3) {
        log_.info("scan", "scheduled daily scan");
        scanner_.start("quick", quickScanRoots());
        std::this_thread::sleep_for(std::chrono::seconds(60));
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
  fileMon_.stop();
  procMon_.stop();
  netMon_.stop();
  scanner_.cancel();
  // Give the scan worker a moment, then force-join via start's join path by
  // waiting until running_ clears (destructor also joins).
  for (int i = 0; i < 50 && scanner_.running(); ++i)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  server_.stop();
  log_.info("system", "daemon stopped");
  return 0;
}

void Daemon::requestStop() { stop_ = true; }

} // namespace oreon
