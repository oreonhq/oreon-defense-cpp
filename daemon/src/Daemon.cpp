#include <oreon/ThreatState.hpp>
#include "Daemon.hpp"
#include "Signature.hpp"
#include "SystemTrust.hpp"
#include "CmdlineHeuristics.hpp"
#include <oreon/Protocol.hpp>
#include <oreon/JsonUtil.hpp>
#include <oreon/Hash.hpp>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <csignal>
#include <thread>
#include <chrono>
#include <algorithm>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include "Guard.hpp"

namespace oreon {
namespace fs = std::filesystem;

static Daemon* gDaemon = nullptr;

static void onSignal(int) {
  if (gDaemon) gDaemon->requestStop();
}

static std::string strParam(const json& p, const char* key, size_t maxLen, bool required = false) {
  if (!p.contains(key) || p[key].is_null()) {
    if (required) throw std::invalid_argument(std::string(key) + " is required");
    return {};
  }
  if (!p[key].is_string()) throw std::invalid_argument(std::string(key) + " must be a string");
  std::string s = p[key].get<std::string>();
  if (s.size() > maxLen) throw std::invalid_argument(std::string(key) + " is too long");
  if (s.find('\0') != std::string::npos) throw std::invalid_argument(std::string(key) + " has a NUL byte");
  return s;
}

static std::string absPath(const std::string& s, const char* key) {
  if (s.empty() || s[0] != '/') throw std::invalid_argument(std::string(key) + " must be an absolute path");
  return fs::path(s).lexically_normal().string();
}

static bool boolParam(const json& p, const char* key, bool& out) {
  if (!p.contains(key)) return false;
  if (!p[key].is_boolean()) throw std::invalid_argument(std::string(key) + " must be true or false");
  out = p[key].get<bool>();
  return true;
}

static int intParam(const json& p, const char* key, int lo, int hi, int def) {
  if (!p.contains(key)) return def;
  if (!p[key].is_number_integer()) throw std::invalid_argument(std::string(key) + " must be an integer");
  long long v = p[key].get<long long>();
  if (v < lo || v > hi) throw std::invalid_argument(std::string(key) + " is out of range");
  return static_cast<int>(v);
}

static std::vector<std::string> pathList(const json& p, const char* key, size_t maxItems) {
  std::vector<std::string> out;
  if (!p.contains(key)) return out;
  if (!p[key].is_array()) throw std::invalid_argument(std::string(key) + " must be a list");
  if (p[key].size() > maxItems) throw std::invalid_argument(std::string(key) + " has too many entries");
  for (const auto& v : p[key]) {
    if (!v.is_string()) throw std::invalid_argument(std::string(key) + " entries must be strings");
    std::string s = v.get<std::string>();
    if (s.size() > 4096 || s.find('\0') != std::string::npos)
      throw std::invalid_argument(std::string(key) + " entry is invalid");
    out.push_back(absPath(s, key));
  }
  return out;
}

static json denied(const std::string& why) {
  return json{{"_error", why.empty() ? "not authorized" : why}, {"_code", "EPERM"}};
}

static bool underDir(const std::string& path, const std::string& dir) {
  if (dir.empty()) return false;
  return path == dir || (path.size() > dir.size() && path.compare(0, dir.size(), dir) == 0 &&
                         path[dir.size()] == '/');
}

static bool systemPath(const std::string& p) {
  for (const char* d : {"/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/etc", "/opt"})
    if (underDir(p, d)) return true;
  return false;
}

Daemon::~Daemon() {
  {
    std::lock_guard<std::mutex> lock(wqMu_);
    stop_ = true;
  }
  wqCv_.notify_all();
  if (worker_.joinable()) worker_.join();
}

void Daemon::post(std::function<void()> fn) {
  {
    std::lock_guard<std::mutex> lock(wqMu_);
    if (wq_.size() > 4096) return;
    wq_.push_back(std::move(fn));
  }
  wqCv_.notify_one();
}

void Daemon::workerLoop() {
  for (;;) {
    std::function<void()> fn;
    {
      std::unique_lock<std::mutex> lock(wqMu_);
      wqCv_.wait(lock, [this] { return stop_ || !wq_.empty(); });
      if (stop_ && wq_.empty()) return;
      fn = std::move(wq_.front());
      wq_.pop_front();
    }
    try {
      fn();
    } catch (const std::exception& e) {
      std::cerr << "worker task failed: " << e.what() << "\n";
    }
  }
}

std::string Daemon::newThreatId() {
  return "thr-" + std::to_string(nowEpoch()) + "-" + std::to_string(++threatSeq_);
}

bool Daemon::init(const std::string& configPath) {
  gDaemon = this;
  std::signal(SIGINT, onSignal);
  std::signal(SIGTERM, onSignal);
  std::signal(SIGPIPE, SIG_IGN);

  if (!config_.load(configPath)) return false;
  auto& cfg = config_.get();

  log_.open(cfg.logPath);
  quarantine_.setDir(cfg.quarantineDir);
  quarantine_.reload();
  worker_ = std::thread([this] { workerLoop(); });

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

  // Always keep our own state out of watches/scans (config may omit these).
  auto ensureExcl = [&](const std::string& p) {
    if (p.empty()) return;
    auto& ex = cfg.exclusions;
    if (std::find(ex.begin(), ex.end(), p) == ex.end()) ex.push_back(p);
  };
  ensureExcl(cfg.dataDir);
  ensureExcl(cfg.quarantineDir);
  ensureExcl("/var/lib/oreon-defense");
  loadAllowList();

  updater_.configure(cfg.rulesUrl, cfg.rulesPublicKey, cfg.dataDir + "/rules/feed");
  updater_.setRulesCallback([this](const RuleSet&) {
    applyRules();
  });
  updater_.setDoneCallback([this](const RuleUpdater::Status& st, bool changed) {
    if (!st.lastError.empty())
      log_.warn("rules", "rule update failed: " + st.lastError);
    else if (changed)
      log_.info("rules", "rules updated to version " + std::to_string(st.version));
    else
      log_.info("rules", "rules checked: " + st.lastResult);
    server_.broadcast(json{{"event", proto::EventRulesUpdate}, {"data", engineJson()["rules"]}});
    broadcastEngine();
  });

  netBlock_.setStatePath(cfg.dataDir + "/blocklist.json");
  netBlock_.loadState();

  applyRules();

  auth_.setAdminGroups(cfg.adminGroups);

  guard_.setCallback([this](const GuardMonitor::Alert& a) { onGuardAlert(a); });
  guard_.setInfoCallback([this](const std::string& path, const std::string& reasons) {
    log_.info("guard", "change accepted: " + reasons, path);
  });

  clam_.setDbDir(cfg.clamavDbDir);
  clam_.setMaxFileMb(cfg.clamavMaxFileMb);
  clam_.setReloadCallback([this](const ClamEngine::Status& s) {
    if (s.available && s.error.empty())
      log_.info("clamav", "signatures loaded: " + std::to_string(s.signatures) +
                " (daily " + std::to_string(s.dailyVersion) + ")", s.dbDir);
    else
      log_.warn("clamav", s.error.empty() ? "signature load failed" : s.error, s.dbDir);
    onAccess_.clearCache();
    {
      std::lock_guard<std::mutex> lock(exeMu_);
      exeClean_.clear();
    }
    broadcastEngine();
  });
  if (cfg.clamavEnabled) clam_.loadAsync();

  scanner_.setRuleEngine(&engine_);
  scanner_.setDetector([this](const std::string& p) { return detect(p); });
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

  onAccess_.setScanFn([this](int fd, const std::string& path, pid_t pid, bool exec) {
    ScanContext ctx;
    ctx.pid = pid;
    ctx.exec = exec;
    Detection d = detectFd(fd, path, ctx);
    if (exec) {
      Detection g = execGate(path, pid);
      if (g.matched && (!d.matched || g.severity > d.severity)) d = g;
    }
    if (d.matched && d.severity >= Severity::High && exec && trust::protectedSystemProgram(path)) {
      d.severity = Severity::Medium;
      d.kill = false;
    }
    if (d.matched && d.severity < Severity::High) {
      Threat t = threatFrom(d, path);
      t.pid = pid;
      post([this, t] { onThreat(t, false); });
      Detection clean;
      clean.cacheable = d.cacheable;
      return clean;
    }
    return d;
  });
  onAccess_.setDenyFn([this](const std::string& path, pid_t pid, bool exec, const Detection& d, bool late) {
    onAccessDenied(path, pid, exec, d, late);
  });

  procMon_.setIntervalMs(cfg.processPollMs);
  procMon_.setRuleEngine(&engine_);
  procMon_.setCallback([this](const ProcessEvent& e) { onProcessEvent(e); });
  procMon_.setModeCallback([this](const std::string& mode, const std::string& err) {
    log_.info("process", "process monitor using " + mode + (err.empty() ? "" : " (" + err + ")"));
    broadcastEngine();
  });

  netMon_.setIntervalMs(cfg.networkPollMs);
  netMon_.setCallback([this](const NetworkEntry& e) { onNetworkEvent(e); });

  server_.setHandler([this](const Peer& peer, const std::string& m, const json& p) {
    return handleRequest(peer, m, p);
  });
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
  applyGuards();

  auto st = updater_.status();
  int64_t interval = int64_t(cfg.rulesUpdateHours) * 3600;
  nextRulesCheck_ = std::max(nowEpoch() + 120, st.lastCheck + interval);

  log_.info("system", "daemon ready (" OREON_VERSION ")");
  return true;
}

void Daemon::applyRules() {
  auto& cfg = config_.get();
  std::vector<RuleSet> sets;
  RuleSet bundled;
  std::string text, err;
  if (readWholeFile(cfg.rulesPath, text) && RuleEngine::parse(text, bundled, &err)) {
    sets.push_back(bundled);
  } else {
    log_.warn("system", "failed to load bundled rules " + err, cfg.rulesPath);
  }
  RuleSet feed;
  if (updater_.loadStored(feed)) sets.push_back(feed);
  RuleSet merged = RuleEngine::merge(sets);
  size_t n = merged.rules.size();
  std::vector<std::pair<std::string, std::string>> bl;
  for (const auto& b : merged.blocklist) bl.emplace_back(b.cidr, b.reason);
  engine_.setRuleSet(std::move(merged));
  netBlock_.setFeed(bl);
  onAccess_.clearCache();
  {
    std::lock_guard<std::mutex> lock(exeMu_);
    exeClean_.clear();
  }
  log_.info("system", "loaded " + std::to_string(n) + " rules (version " +
            std::to_string(engine_.version()) + ")", cfg.rulesPath);
}

std::vector<std::string> Daemon::onAccessExclusions() const {
  const auto& cfg = config_.get();
  std::vector<std::string> out;
  for (const auto& e : cfg.exclusions) {
    bool parent = false;
    for (const auto& p : cfg.onAccessPaths)
      if (p != e && underDir(p, e)) parent = true;
    if (!parent) out.push_back(e);
  }
  out.push_back(cfg.quarantineDir);
  out.push_back(cfg.dataDir);
  return out;
}

void Daemon::applyProtection() {
  auto& cfg = config_.get();
  if (cfg.fileRealtime && status_.fileRealtime) {
    if (!fileMon_.running()) fileMon_.start();
  } else {
    fileMon_.stop();
  }

  bool wantOnAccess = cfg.onAccessBlocking && cfg.fileRealtime && status_.fileRealtime;
  if (wantOnAccess && !onAccess_.running()) {
    onAccess_.setPaths(cfg.onAccessPaths);
    onAccess_.setExclusions(onAccessExclusions());
    onAccess_.setScanOpen(cfg.onAccessScanOpen);
    onAccess_.setTimeoutMs(cfg.onAccessTimeoutMs);
    onAccess_.setMaxFileBytes(uint64_t(cfg.onAccessMaxFileMb) * 1024 * 1024);
    std::string err;
    if (onAccess_.start(&err)) {
      onAccessMode_ = "fanotify";
      onAccessError_.clear();
      auto s = onAccess_.stats();
      log_.info("onaccess", "on-access blocking active (" + s.markMode + " marks" +
                (s.execPerm ? ", exec+open" : ", open only") + ")");
    } else {
      onAccessMode_ = fileMon_.running() ? "inotify" : "off";
      onAccessError_ = err;
      log_.warn("onaccess", "fanotify unavailable, using inotify only: " + err);
    }
  } else if (!wantOnAccess) {
    onAccess_.stop();
    onAccessMode_ = fileMon_.running() ? "inotify" : "off";
    onAccessError_.clear();
  }

  if (cfg.processWatch && status_.processWatch) {
    if (!procMon_.running()) {
      procMon_.start();
    }
  } else {
    procMon_.stop();
  }
  if (cfg.networkWatch && status_.networkWatch) {
    if (!netMon_.running()) netMon_.start();
  } else {
    netMon_.stop();
  }

  if (cfg.networkBlocking && !netBlock_.active()) {
    std::string err;
    if (netBlock_.enable(&err)) {
      netBlockError_.clear();
      log_.info("network", "nftables blocklist active (" + std::to_string(netBlock_.list().size()) + " entries)");
    } else {
      netBlockError_ = err;
      log_.warn("network", "network blocking unavailable: " + err);
    }
  } else if (!cfg.networkBlocking && netBlock_.active()) {
    netBlock_.disable();
    netBlockError_.clear();
  }
}

void Daemon::applyGuards() {
  const auto& cfg = config_.get();
  bool want = cfg.ransomShield || cfg.persistenceGuard || cfg.privEscWatch;
  guard_.setRansomShield(cfg.ransomShield);
  guard_.setPersistenceGuard(cfg.persistenceGuard);
  guard_.setPrivEscWatch(cfg.privEscWatch);
  guard_.setExclusions(cfg.exclusions);
  if (want) {
    guard_.stop();
    if (guard_.start())
      log_.info("guard", "advanced defenses active (ransomware, persistence, privilege watch), writer attribution: " +
                guard_.attributionMode());
  } else {
    guard_.stop();
  }
}

void Daemon::onGuardAlert(const GuardMonitor::Alert& a) {
  Threat t;
  t.id = newThreatId();
  t.kind = "guard";
  t.engine = a.category;
  t.name = a.title;
  t.ruleId = a.category;
  t.path = a.path;
  t.description = a.message + (a.detail.empty() ? "" : " [" + a.detail + "]");
  t.severity = a.severity;
  t.timestamp = nowEpoch();
  t.action = ThreatAction::Detected;
  if (a.pid > 0) t.pid = a.pid;
  log_.alert(a.category, a.severity, a.title + " - " + a.path + " (" + a.reasons + ")", a.path);
  if (a.kill && a.pid > 0 && config_.get().killMalicious) {
    std::string err;
    if (killPid(a.pid, "", &err)) {
      t.action = ThreatAction::Killed;
      log_.alert(a.category, a.severity, "stopped writer pid " + std::to_string(a.pid), a.path);
    } else {
      log_.warn(a.category, "did not stop writer pid " + std::to_string(a.pid) + ": " + err, a.path);
    }
  }
  {
    std::lock_guard<std::mutex> lock(mu_);
    threats_.push_back(t);
    if (threats_.size() > 1000) threats_.erase(threats_.begin(), threats_.begin() + 200);
  }
  server_.broadcast(json{{"event", proto::EventThreat}, {"data", threatToJson(t)}});
  refreshStatus();
  server_.broadcast(json{{"event", proto::EventStatus}, {"data", statusJson()}});
}

void Daemon::refreshStatus() {
  std::lock_guard<std::mutex> lock(mu_);
  status_.quarantineCount = quarantine_.list().size();
  const uint64_t active = countActiveThreats(threats_);
  status_.threatCount = active;
  bool any = status_.fileRealtime || status_.processWatch || status_.networkWatch;
  status_.protectedStatus = any && active == 0;
  if (!any) status_.statusText = "Protection off";
  else if (active > 0) status_.statusText = "At risk";
  else status_.statusText = "Protected";
}

json Daemon::engineJson() {
  const auto& cfg = config_.get();
  auto cs = clam_.status();
  auto os = onAccess_.stats();
  auto rs = updater_.status();
  auto bl = netBlock_.list();
  return json{
    {"version", OREON_VERSION},
    {"clamav", {
      {"enabled", cfg.clamavEnabled},
      {"available", cs.available},
      {"loading", cs.loading},
      {"signatures", cs.signatures},
      {"dailyVersion", cs.dailyVersion},
      {"mainVersion", cs.mainVersion},
      {"dbTime", cs.dbTime},
      {"loadedAt", cs.loadedAt},
      {"dbDir", cs.dbDir.empty() ? cfg.clamavDbDir : cs.dbDir},
      {"libVersion", cs.libVersion},
      {"error", cs.error}
    }},
    {"onAccess", {
      {"enabled", cfg.onAccessBlocking},
      {"mode", onAccessMode_},
      {"error", onAccessError_},
      {"markMode", os.markMode},
      {"execPerm", os.execPerm},
      {"paths", cfg.onAccessPaths},
      {"events", os.events},
      {"scanned", os.scanned},
      {"denied", os.denied},
      {"timeouts", os.timeouts},
      {"cacheHits", os.cacheHits}
    }},
    {"processMonitor", {
      {"mode", procMon_.mode()},
      {"error", procMon_.lastError()},
      {"killMalicious", cfg.killMalicious}
    }},
    {"networkBlocking", {
      {"enabled", cfg.networkBlocking},
      {"active", netBlock_.active()},
      {"available", netBlock_.available()},
      {"count", bl.size()},
      {"table", "inet " + NetBlocker::tableName()},
      {"error", netBlockError_.empty() ? netBlock_.lastError() : netBlockError_}
    }},
    {"rules", {
      {"version", engine_.version()},
      {"count", engine_.ruleCount()},
      {"feedVersion", rs.version},
      {"published", rs.published},
      {"url", rs.url},
      {"autoUpdate", cfg.rulesAutoUpdate},
      {"intervalHours", cfg.rulesUpdateHours},
      {"lastCheck", rs.lastCheck},
      {"lastUpdate", rs.lastUpdate},
      {"lastResult", rs.lastResult},
      {"lastError", rs.lastError},
      {"running", rs.running},
      {"keyPresent", rs.keyPresent}
    }}
  };
}

json Daemon::statusJson() {
  refreshStatus();
  json j;
  {
    std::lock_guard<std::mutex> lock(mu_);
    j = protectionToJson(status_);
  }
  j.update(engineJson());
  return j;
}

void Daemon::broadcastEngine() {
  server_.broadcast(json{{"event", proto::EventStatus}, {"data", statusJson()}});
}

void Daemon::loadAllowList() {
  std::string text;
  if (!readWholeFile(config_.get().dataDir + "/allow.json", text, 1024 * 1024)) return;
  try {
    auto j = json::parse(text);
    for (const auto& v : j.value("paths", json::array())) {
      if (!v.is_string()) continue;
      allowedPaths_.insert(v.get<std::string>());
      engine_.addAllowPath(v.get<std::string>());
    }
  } catch (...) {}
}

void Daemon::saveAllowList() {
  json j{{"paths", std::vector<std::string>(allowedPaths_.begin(), allowedPaths_.end())}};
  writeFileAtomic(config_.get().dataDir + "/allow.json", j.dump(2) + "\n", 0600);
}

bool Daemon::allowed(const std::string& path) {
  if (engine_.isAllowed(path)) return true;
  std::lock_guard<std::mutex> lock(mu_);
  return allowedPaths_.count(path) > 0;
}

Detection Daemon::fromClam(const ClamEngine::Result& r) const {
  Detection d;
  d.matched = true;
  d.name = r.virusName;
  d.ruleId = "clamav";
  d.engine = "clamav";
  d.detail = "ClamAV signature";
  d.description = "ClamAV signature " + r.virusName;
  bool heuristic = r.virusName.rfind("Heuristics.", 0) == 0 || r.virusName.rfind("PUA.", 0) == 0;
  d.severity = heuristic ? Severity::Medium : Severity::High;
  d.kill = !heuristic;
  d.heuristic = heuristic;
  return d;
}

Detection Daemon::fromRule(const MatchResult& m) const {
  Detection d;
  d.matched = true;
  d.name = m.rule.name;
  d.ruleId = m.rule.id;
  d.engine = "rules";
  d.detail = m.detail;
  d.description = m.rule.description;
  d.severity = m.rule.severity;
  d.kill = m.rule.kill;
  d.cacheable = m.cacheable;
  if (m.heuristic) {
    d.heuristic = true;
    d.severity = std::min(d.severity, Severity::Low);
    d.kill = false;
  }
  return d;
}

Threat Daemon::threatFrom(const Detection& d, const std::string& path) {
  Threat t;
  t.id = newThreatId();
  t.name = d.name;
  t.path = path;
  t.ruleId = d.ruleId;
  t.engine = d.engine;
  t.description = d.description + " [" + d.detail + "]";
  t.severity = d.severity;
  t.heuristic = d.heuristic;
  t.timestamp = nowEpoch();
  return t;
}

Detection Daemon::detect(const std::string& path) {
  if (allowed(path)) return {};
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) {
    auto m = engine_.matchFile(path);
    return m.matched ? fromRule(m) : Detection{};
  }
  struct stat st{};
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    return {};
  }
  Detection d = detectFd(fd, path);
  close(fd);
  return d;
}

Detection Daemon::detectFd(int fd, const std::string& path, const ScanContext& ctx) {
  if (allowed(path)) return {};
  if (config_.get().clamavEnabled && clam_.ready()) {
    auto r = clam_.scanFd(fd, path);
    if (r.infected) return fromClam(r);
  }
  auto m = engine_.matchFd(fd, path, ctx);
  if (m.matched) return fromRule(m);
  Detection clean;
  clean.cacheable = m.cacheable;
  return clean;
}

bool Daemon::exeClean(const std::string& exe, Detection& d) {
  struct stat st{};
  if (stat(exe.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return true;
  std::string key = std::to_string(st.st_dev) + ":" + std::to_string(st.st_ino) + ":" +
                    std::to_string(st.st_mtim.tv_sec) + ":" + std::to_string(st.st_size);
  {
    std::lock_guard<std::mutex> lock(exeMu_);
    if (exeClean_.count(key)) return true;
  }
  d = detect(exe);
  if (d.matched) return false;
  std::lock_guard<std::mutex> lock(exeMu_);
  if (exeClean_.size() > 20000) exeClean_.clear();
  exeClean_[key] = nowEpoch();
  return true;
}

bool Daemon::killPid(int pid, const std::string& expectExe, std::string* err) {
  if (pid <= 1 || pid == getpid()) {
    if (err) *err = "refusing to kill this process";
    return false;
  }
  {
    const auto actor = trust::assessActor(pid);
    if (!trust::mayKill(actor)) {
      if (err) *err = "refusing to stop a system program: " + actor.summary();
      return false;
    }
  }
  if (!expectExe.empty()) {
    char link[4096];
    ssize_t n = readlink(("/proc/" + std::to_string(pid) + "/exe").c_str(), link, sizeof(link) - 1);
    if (n > 0) {
      link[n] = 0;
      if (expectExe != link) {
        if (err) *err = "process changed";
        return false;
      }
    }
  }
  if (::kill(pid, SIGKILL) != 0) {
    if (err) *err = strerror(errno);
    return false;
  }
  return true;
}

static std::string originOf(const std::string& path) {
  char buf[4096];
  ssize_t n = getxattr(path.c_str(), "user.xdg.origin.url", buf, sizeof(buf) - 1);
  if (n > 0) return std::string(buf, static_cast<size_t>(n));
  return {};
}

Detection Daemon::execGate(const std::string& path, pid_t pid) {
  const auto& cfg = config_.get();
  if (!cfg.execProtection) return {};
  guard::ExecInputs in;
  in.inDevShm = underDir(path, "/dev/shm");
  in.inTemp = underDir(path, "/tmp") || underDir(path, "/var/tmp");
  in.inDownloads = path.find("/Downloads/") != std::string::npos;
  if (!in.inDevShm && !in.inTemp && !in.inDownloads) return {};
  in.appImage = path.size() > 9 && path.substr(path.size() - 9) == ".AppImage";
  in.allowListed = allowed(path);
  for (const auto& a : cfg.execAllowList)
    if (path == a || path.rfind(a + "/", 0) == 0) in.allowListed = true;
  in.trustedWriter = trust::assessActor(pid).trust == trust::ActorTrust::Trusted;
  auto decision = guard::execDecision(in);
  if (decision == guard::ExecDecision::Allow) return {};
  Detection d;
  d.matched = true;
  d.engine = "exec-guard";
  d.ruleId = "exec-protection";
  d.name = "Unapproved program";
  d.detail = in.inDevShm ? "in /dev/shm" : in.inTemp ? "in a temp folder" : "in Downloads";
  d.description = "A program that is not from a package tried to run " + d.detail;
  if (decision == guard::ExecDecision::Block) {
    d.severity = Severity::High;
    d.kill = true;
    d.heuristic = false;
  } else {
    d.severity = Severity::Low;
    d.kill = false;
    d.heuristic = true;
  }
  d.cacheable = false;
  return d;
}

void Daemon::onFileEvent(const FileEvent& ev) {
  if (ev.op == "delete") return;
  // Never react to our own state or quarantine blobs (avoids re-quarantine loops).
  const auto& cfg = config_.get();
  if (underDir(ev.path, cfg.dataDir) || underDir(ev.path, cfg.quarantineDir)) return;
  if (ev.path.find("/oreon-defense/") != std::string::npos) return;

  // Prefer CLOSE_WRITE; still accept create/modify after a short settle.
  std::this_thread::sleep_for(std::chrono::milliseconds(120));
  struct stat st{};
  if (lstat(ev.path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return;

  if (cfg.ransomShield && (ev.op == "modify" || ev.op == "create")) {
    using namespace std::chrono;
    int64_t nowMs = duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
    if (ransom_.record(ev.path, ev.op, nowMs)) {
      GuardMonitor::Alert a;
      a.category = "ransomware";
      a.severity = Severity::Critical;
      a.title = "A program is changing many files quickly";
      a.message = "A lot of your files are being rewritten in a short time. This can be a sign of ransomware.";
      a.path = ev.path;
      onGuardAlert(a);
    }
  }

  if (cfg.fileScanMaxFileMb > 0 &&
      static_cast<uint64_t>(st.st_size) > uint64_t(cfg.fileScanMaxFileMb) * 1024 * 1024)
    return;

  {
    std::string key = ev.path + "|" + std::to_string(st.st_size) + "|" +
                      std::to_string(st.st_mtim.tv_sec) + "." + std::to_string(st.st_mtim.tv_nsec) +
                      "|" + std::to_string(st.st_mode);
    std::lock_guard<std::mutex> lock(mu_);
    auto it = recentFileHits_.find(key);
    int64_t now = nowEpoch();
    if (it != recentFileHits_.end() && now - it->second < 2) return;
    if (recentFileHits_.size() > 10000) recentFileHits_.clear();
    recentFileHits_[key] = now;
  }

  auto d = detect(ev.path);
  if (!d.matched) return;

  Threat t = threatFrom(d, ev.path);
  t.sha256 = sha256File(ev.path);
  t.originUrl = originOf(ev.path);
  onThreat(t, true);
}

void Daemon::onAccessDenied(const std::string& path, pid_t pid, bool exec, const Detection& d, bool late) {
  post([this, path, pid, exec, d, late] {
    Threat t;
    t.id = newThreatId();
    t.name = d.name;
    t.path = path;
    t.ruleId = d.ruleId;
    t.engine = d.engine;
    t.pid = pid;
    t.description = d.description + " [" + d.detail + "]" +
                    (late ? " (found after the open timeout)"
                          : (exec ? " (execution blocked)" : " (open blocked)"));
    t.severity = d.severity;
    t.heuristic = d.heuristic;
    t.sha256 = sha256File(path);
    t.originUrl = originOf(path);
    t.timestamp = nowEpoch();
    t.action = ThreatAction::Blocked;
    log_.alert("onaccess", d.severity,
               std::string(exec ? "blocked execution of " : "blocked open of ") + d.name +
               " by pid " + std::to_string(pid), path);
    onThreat(t, true);
  });
}

void Daemon::onProcessEvent(const ProcessEvent& ev) {
  post([this, ev] { handleProcess(ev); });
}

void Daemon::handleProcess(const ProcessEvent& ev) {
  const auto& cfg = config_.get();
  ProcessEvent pe = ev;
  const trust::ExeView view = trust::exeView(pe.pid);
  if (view.ok && view.host != pe.exe) {
    ProcessEvent fresh;
    if (ProcessMonitor::readProcess(pe.pid, fresh) && !fresh.exe.empty()) {
      log_.info("process", "exec race: judged again on " + fresh.exe + " (first read " + pe.exe + ")", fresh.exe);
      pe.exe = fresh.exe;
      pe.name = fresh.name;
      pe.argv = fresh.argv;
      pe.cmdline = fresh.cmdline;
      if (pe.ruleId == "reverse-shell") {
        const auto hit = heuristics::strongProcessPattern(pe.argv, pe.exe);
        if (!hit.matched) {
          pe.suspicious = false;
          pe.kill = false;
          pe.reason.clear();
          pe.ruleId.clear();
        } else {
          pe.reason = "reverse shell or remote-control pattern: " + hit.pattern;
        }
      }
    }
  }
  const bool chrooted = view.ok && view.root != "/";
  Detection exeHit;
  bool exeBad = false;
  if (chrooted && !pe.exe.empty() && !allowed(pe.exe)) {
    int fd = open(("/proc/" + std::to_string(pe.pid) + "/exe").c_str(), O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
      exeHit = detectFd(fd, view.inner);
      exeBad = exeHit.matched;
      close(fd);
    }
  } else if (!pe.exe.empty() && !allowed(pe.exe)) {
    std::string exePath = pe.exe;
    const std::string del = " (deleted)";
    if (exePath.size() > del.size() && exePath.compare(exePath.size() - del.size(), del.size(), del) == 0) {
      int fd = open(("/proc/" + std::to_string(pe.pid) + "/exe").c_str(), O_RDONLY | O_CLOEXEC);
      if (fd >= 0) {
        exeHit = detectFd(fd, exePath);
        exeBad = exeHit.matched;
        close(fd);
      }
    } else {
      exeBad = !exeClean(exePath, exeHit);
    }
  }
  if (!pe.suspicious && !exeBad) return;
  if (pe.suspicious && allowed(pe.exe.empty() ? pe.cmdline : pe.exe)) return;
  const trust::ActorVerdict actor = trust::assessActor(pe.pid);
  if (exeBad && exeHit.heuristic && actor.trust == trust::ActorTrust::Trusted) exeBad = false;
  if (!exeBad && !pe.suspicious) return;
  const bool askKill = exeBad ? (exeHit.kill || pe.kill) : pe.kill;
  const trust::ProcessAction verdict = trust::decideProcess(actor, exeBad, askKill);
  {
    std::string why = exeBad ? ("file match rule=" + exeHit.ruleId + " engine=" + exeHit.engine +
                                " name=" + exeHit.name)
                             : std::string();
    if (pe.suspicious)
      why += std::string(why.empty() ? "" : "; ") + "process rule=" +
             (pe.ruleId.empty() ? std::string("process-watch") : pe.ruleId) + " reason=" + pe.reason;
    log_.info("process", "verdict=" + std::string(trust::processActionName(verdict)) +
              " ppid=" + std::to_string(actor.found ? actor.ppid : pe.ppid) +
              " binary=" + trust::systemExeName(actor.exe) + " askKill=" + (askKill ? "yes" : "no") +
              " " + why + " cmdline=" + pe.cmdline.substr(0, 500) + " actor: " + actor.summary(), pe.exe);
  }
  if (verdict == trust::ProcessAction::Ignore) return;
  if (verdict == trust::ProcessAction::AlertOnly) {
    const std::string rule = exeBad ? exeHit.ruleId : pe.ruleId;
    if (!trust::firstInWindow(pe.exe + "|" + rule, nowEpoch(), 60)) return;
  }

  Threat t;
  t.id = newThreatId();
  t.kind = "process";
  t.pid = pe.pid;
  t.path = pe.exe.empty() ? pe.cmdline : pe.exe;
  t.timestamp = nowEpoch();
  t.action = ThreatAction::Detected;
  bool wantKill;
  if (exeBad) {
    t.name = exeHit.name;
    t.ruleId = exeHit.ruleId;
    t.engine = exeHit.engine;
    t.severity = exeHit.severity;
    t.heuristic = exeHit.heuristic;
    t.description = "Running program matched " + exeHit.description + " [" + exeHit.detail + "]";
    wantKill = exeHit.kill;
    if (pe.suspicious && (pe.kill || static_cast<int>(pe.severity) > static_cast<int>(t.severity))) {
      t.name = "Suspicious process: " + pe.name;
      t.ruleId = pe.ruleId.empty() ? "process-watch" : pe.ruleId;
      t.engine = "process";
      t.severity = std::max(t.severity, pe.severity);
      t.heuristic = false;
      t.description = pe.reason + " cmdline: " + pe.cmdline.substr(0, 300) + "; also " + t.description;
      wantKill = wantKill || pe.kill;
    }
  } else {
    t.name = "Suspicious process: " + pe.name;
    t.ruleId = pe.ruleId.empty() ? "process-watch" : pe.ruleId;
    t.engine = "process";
    t.severity = pe.severity;
    t.heuristic = pe.ruleId == "process-heuristic";
    t.description = pe.reason + " cmdline: " + pe.cmdline.substr(0, 300);
    wantKill = pe.kill;
  }

  {
    std::string chain;
    for (const auto& r : actor.reasons) chain += (chain.empty() ? "" : "\n") + r;
    t.description += "\n\nVerdict: " + std::string(trust::actorTrustName(actor.trust)) +
                     (actor.chrootRoot.empty() ? std::string() : " (chroot " + actor.chrootRoot + ")") +
                     "\n" + chain;
  }
  if (verdict != trust::ProcessAction::AlertAndKill) wantKill = false;
  if (wantKill && cfg.killMalicious) {
    std::string err;
    if (killPid(pe.pid, pe.exe, &err)) {
      t.action = ThreatAction::Killed;
      log_.alert("process", t.severity, "killed pid " + std::to_string(pe.pid) + " (" + t.name + ")", t.path);
    } else {
      log_.warn("process", "could not kill pid " + std::to_string(pe.pid) + ": " + err, t.path);
    }
  }
  if (exeBad && t.severity >= Severity::High && !systemPath(pe.exe)) {
    auto q = quarantine_.quarantineFile(pe.exe, t);
    if (q) {
      if (t.action != ThreatAction::Killed) t.action = ThreatAction::Quarantined;
      t.quarantineId = q->id;
    }
  }
  log_.alert("process", t.severity, t.name + " - " + t.description, t.path);
  {
    std::lock_guard<std::mutex> lock(mu_);
    threats_.push_back(t);
    if (threats_.size() > 1000) threats_.erase(threats_.begin(), threats_.begin() + 200);
  }
  server_.broadcast(json{{"event", proto::EventThreat}, {"data", threatToJson(t)}});
  refreshStatus();
  server_.broadcast(json{{"event", proto::EventStatus}, {"data", statusJson()}});
}

static std::string hostOf(const std::string& addrPort) {
  if (!addrPort.empty() && addrPort[0] == '[') {
    auto e = addrPort.find(']');
    return e == std::string::npos ? addrPort : addrPort.substr(1, e - 1);
  }
  auto c = addrPort.rfind(':');
  return c == std::string::npos ? addrPort : addrPort.substr(0, c);
}

void Daemon::onNetworkEvent(const NetworkEntry& ev) {
  std::string ip = hostOf(ev.remoteAddr);
  bool blocked = !ip.empty() && netBlock_.isBlocked(ip);
  if (ev.risk != "high" && !blocked) return;
  log_.warn("network", std::string(blocked ? "connection to blocked address " : "risky connection ") +
            ev.process + " " + ev.remoteAddr);
  server_.broadcast(json{
    {"event", proto::EventNetwork},
    {"data", {
      {"proto", ev.proto},
      {"localAddr", ev.localAddr},
      {"remoteAddr", ev.remoteAddr},
      {"remoteIp", ip},
      {"state", ev.state},
      {"pid", ev.pid},
      {"process", ev.process},
      {"risk", blocked ? std::string("blocked") : ev.risk}
    }}
  });
}

void Daemon::onThreat(Threat t, bool autoQuarantine) {
  if (t.id.empty()) t.id = newThreatId();
  if (allowed(t.path)) {
    t.action = ThreatAction::Allowed;
    return;
  }
  // Skip if this path was already handled (detected/quarantined) moments ago.
  {
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto& existing : threats_) {
      if (existing.path == t.path &&
          (existing.action == ThreatAction::Detected ||
           existing.action == ThreatAction::Quarantined ||
           existing.action == ThreatAction::Blocked) &&
          t.timestamp - existing.timestamp < 5) {
        return;
      }
    }
  }
  if (autoQuarantine && t.severity >= Severity::High) {
    std::string qerr;
    auto q = quarantine_.quarantineFile(t.path, t, &qerr);
    if (q) {
      t.action = ThreatAction::Quarantined;
      t.quarantineId = q->id;
      log_.alert("threat", t.severity, "quarantined " + t.name, t.path);
    } else {
      log_.alert("threat", t.severity, "detected " + t.name + " (quarantine failed: " + qerr + ")", t.path);
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
    if (threats_.size() > 1000) threats_.erase(threats_.begin(), threats_.begin() + 200);
  }
  refreshStatus();
  server_.broadcast(json{{"event", proto::EventThreat}, {"data", threatToJson(t)}});
  server_.broadcast(json{{"event", proto::EventStatus}, {"data", statusJson()}});
}

std::vector<std::string> Daemon::quickScanRoots() const {
  // Prefer configured watch paths so systemd (root) scans real user homes,
  // not only /root/Downloads.
  const auto& watches = config_.get().watchPaths;
  if (!watches.empty()) {
    std::vector<std::string> roots = watches;
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
    return {"/home", "/root", "/tmp", "/var/tmp", "/dev/shm", "/opt", "/srv"};
  return {homeDir()};
}

json Daemon::handleRequest(const Peer& peer, const std::string& method, const json& params) {
  using namespace proto;
  std::string why;
  auto& cfg = config_.get();

  if (method == MethodPing) return json{{"pong", true}, {"version", OREON_VERSION}};

  if (method == MethodWhoAmI) {
    return json{{"uid", peer.uid}, {"pid", peer.pid},
                {"privileged", auth_.isOwnerOrRoot(peer)},
                {"polkit", auth_.polkitAvailable()}};
  }

  if (method == MethodGetStatus || method == MethodGetEngineStatus) return statusJson();

  if (method == MethodSetProtection) {
    bool f = status_.fileRealtime, p = status_.processWatch, n = status_.networkWatch;
    boolParam(params, "fileRealtime", f);
    boolParam(params, "processWatch", p);
    boolParam(params, "networkWatch", n);
    bool turningOff = (!f && status_.fileRealtime) || (!p && status_.processWatch) ||
                      (!n && status_.networkWatch);
    if (turningOff && !auth_.authorize(peer, PeerAuth::ActionManage, &why)) return denied(why);
    status_.fileRealtime = f;
    status_.processWatch = p;
    status_.networkWatch = n;
    cfg.fileRealtime = f;
    cfg.processWatch = p;
    cfg.networkWatch = n;
    config_.save();
    applyProtection();
    log_.info("system", std::string("protection changed by uid ") + std::to_string(peer.uid));
    auto st = statusJson();
    server_.broadcast(json{{"event", EventStatus}, {"data", st}});
    return st;
  }

  if (method == MethodSetOptions) {
    if (!auth_.authorize(peer, PeerAuth::ActionManage, &why)) return denied(why);
    bool v;
    bool restartOnAccess = false;
    if (boolParam(params, "onAccessBlocking", v)) { cfg.onAccessBlocking = v; restartOnAccess = true; }
    if (boolParam(params, "onAccessScanOpen", v)) { cfg.onAccessScanOpen = v; restartOnAccess = true; }
    if (boolParam(params, "killMalicious", v)) cfg.killMalicious = v;
    if (boolParam(params, "networkBlocking", v)) cfg.networkBlocking = v;
    if (boolParam(params, "rulesAutoUpdate", v)) cfg.rulesAutoUpdate = v;
    bool defenseChanged = false;
    if (boolParam(params, "ransomShield", v)) { cfg.ransomShield = v; defenseChanged = true; }
    if (boolParam(params, "execProtection", v)) { cfg.execProtection = v; defenseChanged = true; }
    if (boolParam(params, "persistenceGuard", v)) { cfg.persistenceGuard = v; defenseChanged = true; }
    if (boolParam(params, "revShellWatch", v)) cfg.revShellWatch = v;
    if (boolParam(params, "privEscWatch", v)) cfg.privEscWatch = v;
    if (boolParam(params, "clamavEnabled", v)) {
      bool was = cfg.clamavEnabled;
      cfg.clamavEnabled = v;
      if (v && !was && !clam_.ready()) clam_.loadAsync();
      onAccess_.clearCache();
    }
    cfg.rulesUpdateHours = intParam(params, "rulesUpdateHours", 1, 24 * 7, cfg.rulesUpdateHours);
    cfg.fileScanMaxFileMb = intParam(params, "fileScanMaxFileMb", 1, 4096, cfg.fileScanMaxFileMb);
    config_.save();
    if (restartOnAccess) onAccess_.stop();
    applyProtection();
    if (defenseChanged) applyGuards();
    log_.info("system", "options changed by uid " + std::to_string(peer.uid));
    broadcastEngine();
    return statusJson();
  }

  if (method == MethodStartScan) {
    std::string type = strParam(params, "type", 16);
    if (type.empty()) type = "quick";
    std::vector<std::string> roots;
    if (type == "custom") {
      roots = pathList(params, "paths", 64);
      std::string one = strParam(params, "path", 4096);
      if (!one.empty()) roots.push_back(absPath(one, "path"));
    } else if (type == "full") {
      roots = fullScanRoots();
    } else if (type == "quick") {
      roots = quickScanRoots();
    } else {
      return json{{"_error", "unknown scan type"}};
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
    std::string path = strParam(params, "path", 4096);
    std::string id = strParam(params, "id", 128);
    if (!path.empty()) path = absPath(path, "path");
    Threat t;
    bool known = false;
    {
      std::lock_guard<std::mutex> lock(mu_);
      for (auto& x : threats_) {
        if ((!id.empty() && x.id == id) || (!path.empty() && x.path == path)) {
          t = x;
          known = true;
          break;
        }
      }
    }
    if (t.path.empty()) t.path = path;
    if (t.path.empty() || t.path[0] != '/') return json{{"_error", "path required"}};
    struct stat st{};
    if (lstat(t.path.c_str(), &st) != 0) return json{{"_error", "file not found"}};
    if (!S_ISREG(st.st_mode)) return json{{"_error", "not a regular file"}};
    const char* action = (known || st.st_uid == peer.uid) ? PeerAuth::ActionQuarantine
                                                         : PeerAuth::ActionManage;
    if (!auth_.authorize(peer, action, &why)) return denied(why);
    if (t.name.empty()) t.name = "Manual quarantine";
    t.severity = known ? t.severity : Severity::High;
    std::string qerr;
    auto q = quarantine_.quarantineFile(t.path, t, &qerr);
    if (!q) {
      log_.warn("threat", "quarantine failed: " + qerr, t.path);
      return json{{"_error", "Could not quarantine: " + qerr}};
    }
    {
      std::lock_guard<std::mutex> lock(mu_);
      for (auto& x : threats_) {
        if ((!id.empty() && x.id == id) || x.path == t.path) {
          x.action = ThreatAction::Quarantined;
          x.quarantineId = q->id;
        }
      }
    }
    log_.info("threat", "quarantined by uid " + std::to_string(peer.uid), t.path);
    refreshStatus();
    return quarantineToJson(*q);
  }

  if (method == MethodRestore) {
    if (!auth_.authorize(peer, PeerAuth::ActionManage, &why)) return denied(why);
    std::string id = strParam(params, "id", 128, true);
    auto item = quarantine_.get(id);
    if (!item) return json{{"_error", "not found"}};
    {
      std::lock_guard<std::mutex> lock(mu_);
      allowedPaths_.insert(item->originalPath);
      saveAllowList();
    }
    engine_.addAllowPath(item->originalPath);
    onAccess_.clearCache();
    std::string err;
    if (!quarantine_.restore(id, &err)) return json{{"_error", err}};
    {
      std::lock_guard<std::mutex> lock(mu_);
      for (auto& x : threats_)
        if (x.quarantineId == id) x.action = ThreatAction::Restored;
    }
    log_.info("threat", "restored by uid " + std::to_string(peer.uid), item->originalPath);
    refreshStatus();
    return json{{"restored", true}};
  }

  if (method == MethodDeleteQuarantine) {
    std::string id = strParam(params, "id", 128, true);
    auto item = quarantine_.get(id);
    if (!item) return json{{"_error", "not found"}};
    bool ownerOrActive = auth_.isOwnerOrRoot(peer) ||
                         (item->ownerUid >= 0 && peer.uid == static_cast<uid_t>(item->ownerUid)) ||
                         auth_.isActiveLocalSession(peer);
    if (!ownerOrActive && !auth_.authorize(peer, PeerAuth::ActionDelete, &why)) return denied(why);
    std::string err;
    if (!quarantine_.remove(id, &err)) return json{{"_error", err}};
    {
      std::lock_guard<std::mutex> lock(mu_);
      for (auto& x : threats_)
        if (x.quarantineId == id) x.action = ThreatAction::Deleted;
    }
    log_.info("threat", "deleted quarantine item " + id + " by uid " + std::to_string(peer.uid));
    refreshStatus();
    return json{{"deleted", true}};
  }

  if (method == MethodAllow) {
    if (!auth_.authorize(peer, PeerAuth::ActionManage, &why)) return denied(why);
    std::string path = absPath(strParam(params, "path", 4096, true), "path");
    if (path == "/") return json{{"_error", "refusing to allow /"}};
    engine_.addAllowPath(path);
    onAccess_.clearCache();
    std::lock_guard<std::mutex> lock(mu_);
    allowedPaths_.insert(path);
    saveAllowList();
    for (auto& t : threats_)
      if (t.path == path) t.action = ThreatAction::Allowed;
    log_.info("threat", "allowed by uid " + std::to_string(peer.uid), path);
    return json{{"allowed", true}};
  }

  if (method == MethodKillProcess) {
    int pid = intParam(params, "pid", 2, 1 << 22, 0);
    if (pid <= 1) return json{{"_error", "pid required"}};
    struct stat st{};
    if (stat(("/proc/" + std::to_string(pid)).c_str(), &st) != 0) return json{{"_error", "no such process"}};
    if (st.st_uid != peer.uid && !auth_.authorize(peer, PeerAuth::ActionManage, &why)) return denied(why);
    std::string err;
    if (!killPid(pid, "", &err)) return json{{"_error", err}};
    {
      std::lock_guard<std::mutex> lock(mu_);
      for (auto& x : threats_)
        if (x.kind == "process" && x.pid == pid) x.action = ThreatAction::Killed;
    }
    log_.alert("process", Severity::Medium, "killed pid " + std::to_string(pid) + " on request of uid " +
               std::to_string(peer.uid));
    refreshStatus();
    return json{{"killed", true}};
  }

  if (method == MethodGetNetwork) {
    json arr = json::array();
    for (const auto& e : netMon_.snapshot()) {
      std::string ip = hostOf(e.remoteAddr);
      bool blocked = e.state != "LISTEN" && netBlock_.isBlocked(ip);
      arr.push_back({
        {"proto", e.proto},
        {"localAddr", e.localAddr},
        {"remoteAddr", e.remoteAddr},
        {"remoteIp", ip},
        {"state", e.state},
        {"pid", e.pid},
        {"process", e.process},
        {"risk", blocked ? std::string("blocked") : e.risk}
      });
    }
    return json{{"entries", arr}};
  }

  if (method == MethodGetBlocklist) {
    json arr = json::array();
    for (const auto& e : netBlock_.list())
      arr.push_back({{"cidr", e.cidr}, {"reason", e.reason}, {"source", e.source}, {"added", e.added}});
    return json{{"entries", arr}, {"active", netBlock_.active()}};
  }

  if (method == MethodBlockIp) {
    if (!auth_.authorize(peer, PeerAuth::ActionNetwork, &why)) return denied(why);
    std::string ip = strParam(params, "ip", 64, true);
    std::string reason = strParam(params, "reason", 200);
    std::string err;
    if (!netBlock_.block(ip, reason.empty() ? "blocked by user" : reason, &err))
      return json{{"_error", err}};
    log_.alert("network", Severity::Medium, "blocked " + ip + " by uid " + std::to_string(peer.uid));
    server_.broadcast(json{{"event", EventBlocklist}, {"data", {{"ip", ip}, {"blocked", true}}}});
    return json{{"blocked", true}, {"active", netBlock_.active()}};
  }

  if (method == MethodUnblockIp) {
    if (!auth_.authorize(peer, PeerAuth::ActionManage, &why)) return denied(why);
    std::string ip = strParam(params, "ip", 64, true);
    std::string err;
    if (!netBlock_.unblock(ip, &err)) return json{{"_error", err}};
    log_.info("network", "unblocked " + ip + " by uid " + std::to_string(peer.uid));
    server_.broadcast(json{{"event", EventBlocklist}, {"data", {{"ip", ip}, {"blocked", false}}}});
    return json{{"unblocked", true}};
  }

  if (method == MethodGetHistory) {
    std::string search = strParam(params, "search", 256);
    int limit = intParam(params, "limit", 1, 5000, 500);
    json arr = json::array();
    for (const auto& e : log_.query(search, static_cast<size_t>(limit))) arr.push_back(logToJson(e));
    return json{{"events", arr}};
  }

  if (method == MethodGetConfig) {
    const auto& c = cfg;
    return json{
      {"watchPaths", c.watchPaths},
      {"exclusions", c.exclusions},
      {"rulesPath", c.rulesPath},
      {"scheduleHour", c.scheduleHour},
      {"scheduleMinute", c.scheduleMinute},
      {"scheduleType", c.scheduleType},
      {"fileRealtime", c.fileRealtime},
      {"processWatch", c.processWatch},
      {"networkWatch", c.networkWatch},
      {"onAccessBlocking", c.onAccessBlocking},
      {"onAccessScanOpen", c.onAccessScanOpen},
      {"onAccessPaths", c.onAccessPaths},
      {"killMalicious", c.killMalicious},
      {"networkBlocking", c.networkBlocking},
      {"clamavEnabled", c.clamavEnabled},
      {"rulesAutoUpdate", c.rulesAutoUpdate},
      {"rulesUrl", c.rulesUrl},
      {"rulesUpdateHours", c.rulesUpdateHours},
      {"fileScanMaxFileMb", c.fileScanMaxFileMb},
      {"ransomShield", c.ransomShield},
      {"execProtection", c.execProtection},
      {"persistenceGuard", c.persistenceGuard},
      {"revShellWatch", c.revShellWatch},
      {"privEscWatch", c.privEscWatch},
      {"execAllowList", c.execAllowList}
    };
  }

  if (method == MethodSetConfig) {
    if (!auth_.authorize(peer, PeerAuth::ActionManage, &why)) return denied(why);
    auto& c = cfg;
    if (params.contains("watchPaths")) c.watchPaths = pathList(params, "watchPaths", 256);
    if (params.contains("exclusions")) {
      c.exclusions = pathList(params, "exclusions", 1024);
      for (const auto& p : {c.dataDir, c.quarantineDir, std::string("/var/lib/oreon-defense")})
        if (std::find(c.exclusions.begin(), c.exclusions.end(), p) == c.exclusions.end())
          c.exclusions.push_back(p);
    }
    if (params.contains("onAccessPaths")) c.onAccessPaths = pathList(params, "onAccessPaths", 64);
    if (params.contains("execAllowList")) c.execAllowList = pathList(params, "execAllowList", 256);
    c.scheduleHour = intParam(params, "scheduleHour", -1, 23, c.scheduleHour);
    c.scheduleMinute = intParam(params, "scheduleMinute", 0, 59, c.scheduleMinute);
    if (params.contains("scheduleType")) {
      std::string st = strParam(params, "scheduleType", 16);
      if (st != "none" && st != "daily") return json{{"_error", "scheduleType must be none or daily"}};
      c.scheduleType = st;
    }
    config_.save();
    fileMon_.stop();
    fileMon_.setPaths(c.watchPaths);
    fileMon_.setExclusions(c.exclusions);
    scanner_.setExclusions(c.exclusions);
    onAccess_.stop();
    applyProtection();
    applyGuards();
    log_.info("system", "settings changed by uid " + std::to_string(peer.uid));
    return json{{"saved", true}};
  }

  if (method == MethodUpdateRules) {
    std::string path = strParam(params, "path", 4096);
    bool reload = false;
    boolParam(params, "reloadOnly", reload);
    if (!path.empty() || reload) {
      if (!auth_.authorize(peer, PeerAuth::ActionManage, &why)) return denied(why);
      if (!path.empty()) {
        path = absPath(path, "path");
        std::string text, err;
        RuleSet test;
        if (!readWholeFile(path, text) || !RuleEngine::parse(text, test, &err))
          return json{{"_error", "load failed: " + err}};
        cfg.rulesPath = path;
        config_.save();
      }
      applyRules();
      broadcastEngine();
      return json{{"rules", engine_.ruleCount()}, {"version", engine_.version()}};
    }
    bool force = false;
    boolParam(params, "force", force);
    if (!auth_.isOwnerOrRoot(peer)) {
      std::lock_guard<std::mutex> lock(mu_);
      if (nowEpoch() - lastManualUpdate_ < 15) return json{{"_error", "an update was just requested, try again shortly"}};
      lastManualUpdate_ = nowEpoch();
    }
    if (!updater_.startAsync(force)) return json{{"_error", "update already running"}};
    log_.info("rules", "rule update requested by uid " + std::to_string(peer.uid));
    return json{{"started", true}, {"url", cfg.rulesUrl}};
  }

  return json{{"_error", "unknown method"}};
}

int Daemon::run() {
  int64_t lastClamCheck = nowEpoch();
  while (!stop_) {
    auto& c = config_.get();
    if (c.scheduleType == "daily" && c.scheduleHour >= 0 && !scanner_.running()) {
      time_t now = time(nullptr);
      tm lt{};
      localtime_r(&now, &lt);
      if (lt.tm_hour == c.scheduleHour && lt.tm_min == c.scheduleMinute && lt.tm_sec < 3) {
        log_.info("scan", "scheduled daily scan");
        scanner_.start("quick", quickScanRoots());
        for (int i = 0; i < 120 && !stop_; ++i)
          std::this_thread::sleep_for(std::chrono::milliseconds(500));
      }
    }
    int64_t now = nowEpoch();
    if (c.clamavEnabled && now - lastClamCheck >= 60) {
      lastClamCheck = now;
      if (clam_.checkForUpdates()) log_.info("clamav", "signature database changed, reloading");
    }
    if (c.rulesAutoUpdate && now >= nextRulesCheck_) {
      nextRulesCheck_ = now + int64_t(c.rulesUpdateHours) * 3600;
      updater_.startAsync(false);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
  onAccess_.stop();
  fileMon_.stop();
  procMon_.stop();
  netMon_.stop();
  guard_.stop();
  netBlock_.disable();
  scanner_.cancel();
  for (int i = 0; i < 50 && scanner_.running(); ++i)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  updater_.join();
  clam_.shutdown();
  server_.stop();
  log_.info("system", "daemon stopped");
  return 0;
}

void Daemon::requestStop() { stop_ = true; }

} // namespace oreon
