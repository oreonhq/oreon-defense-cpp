#include "RuleEngine.hpp"
#include "SystemTrust.hpp"
#include <oreon/Hash.hpp>
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>
#include <optional>

namespace oreon {

static constexpr size_t kHeadBytes = 1024 * 1024;

static bool hasRegexMeta(const std::string& s) {
  return s.find_first_of("\\^$.|?*+()[]{}") != std::string::npos;
}

static std::vector<Pattern> compile(const std::vector<std::string>& src, bool icase) {
  std::vector<Pattern> out;
  for (const auto& p : src) {
    Pattern pat;
    pat.text = p;
    if (hasRegexMeta(p)) {
      try {
        auto flags = std::regex::ECMAScript | std::regex::optimize;
        if (icase) flags |= std::regex::icase;
        pat.re = std::make_shared<std::regex>(p, flags);
        pat.literal = false;
      } catch (...) {
        pat.literal = true;
      }
    }
    if (pat.literal && icase) {
      std::transform(pat.text.begin(), pat.text.end(), pat.text.begin(), ::tolower);
    }
    out.push_back(std::move(pat));
  }
  return out;
}

static std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), ::tolower);
  return s;
}

bool RuleEngine::parse(const std::string& yamlText, RuleSet& out, std::string* err) {
  try {
    YAML::Node root = YAML::Load(yamlText);
    if (!root || !root.IsMap()) {
      if (err) *err = "rules document is not a map";
      return false;
    }
    RuleSet rs;
    rs.version = root["version"].as<int64_t>(0);
    rs.published = root["published"].as<std::string>("");
    auto rulesNode = root["rules"];
    if (!rulesNode || !rulesNode.IsSequence()) {
      if (err) *err = "missing rules list";
      return false;
    }
    auto list = [](const YAML::Node& n) {
      std::vector<std::string> v;
      if (n && n.IsSequence())
        for (const auto& x : n) v.push_back(x.as<std::string>());
      return v;
    };
    for (const auto& n : rulesNode) {
      Rule r;
      r.id = n["id"].as<std::string>("");
      r.name = n["name"].as<std::string>(r.id);
      r.description = n["description"].as<std::string>("");
      r.severity = severityFromString(n["severity"].as<std::string>("medium"));
      r.enabled = n["enabled"].as<bool>(true);
      r.elfHeuristic = n["elf_heuristic"].as<bool>(false);
      r.autostartHeuristic = n["autostart_heuristic"].as<bool>(false);
      r.kill = n["kill"].as<bool>(r.severity >= Severity::High);
      r.killCmdline = n["kill_cmdline"].as<bool>(false);
      r.hashes = list(n["hashes"]);
      for (auto& h : r.hashes) h = lower(h);
      r.pathPatterns = list(n["path_patterns"]);
      r.cmdlinePatterns = list(n["cmdline_patterns"]);
      r.namePatterns = list(n["name_patterns"]);
      r.contentPatterns = list(n["content_patterns"]);
      r.pathRe = compile(r.pathPatterns, true);
      r.cmdlineRe = compile(r.cmdlinePatterns, true);
      r.nameRe = compile(r.namePatterns, true);
      r.contentRe = compile(r.contentPatterns, false);
      if (!r.id.empty()) rs.rules.push_back(std::move(r));
    }
    auto nb = root["network_blocklist"];
    if (nb && nb.IsSequence()) {
      for (const auto& e : nb) {
        BlockEntry b;
        if (e.IsScalar()) {
          b.cidr = e.as<std::string>();
        } else if (e.IsMap()) {
          b.cidr = e["ip"].as<std::string>(e["cidr"].as<std::string>(""));
          b.reason = e["reason"].as<std::string>("");
        }
        if (!b.cidr.empty()) rs.blocklist.push_back(b);
      }
    }
    out = std::move(rs);
    return true;
  } catch (const std::exception& e) {
    if (err) *err = e.what();
    return false;
  }
}

RuleSet RuleEngine::merge(const std::vector<RuleSet>& sets) {
  RuleSet out;
  for (const auto& s : sets) {
    out.version = std::max(out.version, s.version);
    if (!s.published.empty()) out.published = s.published;
    for (const auto& r : s.rules) {
      auto it = std::find_if(out.rules.begin(), out.rules.end(),
                             [&](const Rule& x) { return x.id == r.id; });
      if (it != out.rules.end()) *it = r;
      else out.rules.push_back(r);
    }
    for (const auto& b : s.blocklist) {
      bool dup = std::any_of(out.blocklist.begin(), out.blocklist.end(),
                             [&](const BlockEntry& x) { return x.cidr == b.cidr; });
      if (!dup) out.blocklist.push_back(b);
    }
  }
  return out;
}

bool RuleEngine::loadFile(const std::string& path) {
  std::ifstream in(path);
  if (!in) {
    std::cerr << "rules file missing: " << path << "\n";
    return false;
  }
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return loadYaml(text);
}

bool RuleEngine::loadYaml(const std::string& yamlText) {
  RuleSet rs;
  std::string err;
  if (!parse(yamlText, rs, &err)) {
    std::cerr << "rules parse error: " << err << "\n";
    return false;
  }
  setRuleSet(std::move(rs));
  return true;
}

void RuleEngine::setRuleSet(RuleSet rs) {
  std::lock_guard<std::mutex> lock(mu_);
  rules_ = std::move(rs.rules);
  version_ = rs.version;
  blocklist_ = std::move(rs.blocklist);
}

size_t RuleEngine::ruleCount() const {
  std::lock_guard<std::mutex> lock(mu_);
  return rules_.size();
}

int64_t RuleEngine::version() const {
  std::lock_guard<std::mutex> lock(mu_);
  return version_;
}

std::vector<BlockEntry> RuleEngine::blocklist() const {
  std::lock_guard<std::mutex> lock(mu_);
  return blocklist_;
}

std::vector<Rule> RuleEngine::rules() const {
  std::lock_guard<std::mutex> lock(mu_);
  return rules_;
}

bool RuleEngine::needsHash() const {
  std::lock_guard<std::mutex> lock(mu_);
  for (const auto& r : rules_)
    if (r.enabled && !r.hashes.empty()) return true;
  return false;
}

void RuleEngine::addAllowPath(const std::string& path) {
  std::lock_guard<std::mutex> lock(mu_);
  allowPaths_.push_back(path);
}

bool RuleEngine::isAllowed(const std::string& path) const {
  std::lock_guard<std::mutex> lock(mu_);
  for (const auto& a : allowPaths_) {
    if (a.empty()) continue;
    if (path == a || (path.compare(0, a.size(), a) == 0 && (a.back() == '/' || path[a.size()] == '/')))
      return true;
  }
  return false;
}

bool RuleEngine::anyMatch(const std::vector<Pattern>& pats, const std::string& s) {
  std::string ls;
  bool haveLower = false;
  for (const auto& p : pats) {
    if (p.literal) {
      if (s.find(p.text) != std::string::npos) return true;
      if (!haveLower) { ls = lower(s); haveLower = true; }
      if (ls.find(p.text) != std::string::npos) return true;
    } else if (p.re) {
      try {
        if (std::regex_search(s, *p.re)) return true;
      } catch (...) {}
    }
  }
  return false;
}

static std::string hexDigest(const unsigned char* h, unsigned len) {
  std::ostringstream oss;
  for (unsigned i = 0; i < len; ++i)
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(h[i]);
  return oss.str();
}

static std::string sha256Fd(int fd) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return {};
  EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
  char buf[65536];
  off_t off = 0;
  for (;;) {
    ssize_t n = pread(fd, buf, sizeof(buf), off);
    if (n < 0) { EVP_MD_CTX_free(ctx); return {}; }
    if (n == 0) break;
    EVP_DigestUpdate(ctx, buf, static_cast<size_t>(n));
    off += n;
  }
  unsigned char h[EVP_MAX_MD_SIZE];
  unsigned len = 0;
  EVP_DigestFinal_ex(ctx, h, &len);
  EVP_MD_CTX_free(ctx);
  return hexDigest(h, len);
}

static std::string readHead(int fd) {
  std::string buf(kHeadBytes, '\0');
  size_t got = 0;
  while (got < buf.size()) {
    ssize_t n = pread(fd, buf.data() + got, buf.size() - got, static_cast<off_t>(got));
    if (n <= 0) break;
    got += static_cast<size_t>(n);
  }
  buf.resize(got);
  return buf;
}

MatchResult RuleEngine::matchFile(const std::string& path, const std::string& sha256In) {
  MatchResult out;
  if (isAllowed(path)) return out;
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) {
    return matchData(path, sha256In, {}, false, -1, nullptr, {});
  }
  struct stat st{};
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    return out;
  }
  std::string head = readHead(fd);
  std::string hash = sha256In;
  if (hash.empty() && needsHash()) hash = sha256Fd(fd);
  bool elf = head.size() >= 4 && head.compare(0, 4, "\x7f" "ELF") == 0;
  out = matchData(path, lower(hash), head, elf, fd, &st, {});
  close(fd);
  return out;
}

MatchResult RuleEngine::matchFd(int fd, const std::string& path, const ScanContext& ctx) {
  MatchResult out;
  if (isAllowed(path)) return out;
  std::string head = readHead(fd);
  std::string hash = needsHash() ? sha256Fd(fd) : std::string();
  bool elf = head.size() >= 4 && head.compare(0, 4, "\x7f" "ELF") == 0;
  struct stat st{};
  bool haveStat = fstat(fd, &st) == 0;
  return matchData(path, hash, head, elf, fd, haveStat ? &st : nullptr, ctx);
}

static bool elfDropZone(const std::string& path) {
  for (const char* d : {"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"})
    if (path.compare(0, strlen(d), d) == 0) return true;
  return path.find("/Downloads/") != std::string::npos || path.find("/Desktop/") != std::string::npos;
}

static bool homeArea(const std::string& path) {
  for (const char* d : {"/home/", "/var/home/", "/root/", "/run/user/"})
    if (path.compare(0, strlen(d), d) == 0) return true;
  return false;
}

static bool elfDropSuspicious(const std::string& path, int fd, const struct stat* st,
                              const ScanContext& ctx, bool& cacheable) {
  if (!st || !S_ISREG(st->st_mode) || !elfDropZone(path)) return false;
  std::string base = path.substr(path.find_last_of('/') + 1);
  bool oddName = base.find('.') == std::string::npos ||
                 base.find("update") != std::string::npos ||
                 base.find("payload") != std::string::npos ||
                 base.find("miner") != std::string::npos;
  if (!oddName) return false;
  if (!(st->st_mode & 0111) && !ctx.exec) {
    cacheable = false;
    return false;
  }
  if (!trust::droppableByUser(path, *st)) return false;
  if (trust::systemStagingPath(path)) return false;
  if (st->st_uid == 0 && !homeArea(path) && trust::packageTransactionActive()) return false;
  if (trust::copyOfSystemFile(fd, path, *st)) return false;
  return true;
}

MatchResult RuleEngine::matchData(const std::string& path, const std::string& hash,
                                  const std::string& head, bool isElf, int fd,
                                  const struct stat* st, const ScanContext& ctx) const {
  MatchResult out;
  const bool autostart = trust::isAutostartEntry(path);
  std::optional<Rule> autoRule, elfRule;
  {
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto& r : rules_) {
      if (!r.enabled) continue;

      if (!hash.empty()) {
        for (const auto& h : r.hashes) {
          if (h == hash) {
            out.matched = true;
            out.rule = r;
            out.detail = "hash match";
            return out;
          }
        }
      }

      if (!r.pathRe.empty() && anyMatch(r.pathRe, path)) {
        if (autostart) {
          if (!autoRule) autoRule = r;
        } else {
          out.matched = true;
          out.rule = r;
          out.detail = "path pattern";
          return out;
        }
      }

      if (!r.contentRe.empty() && !head.empty()) {
        for (const auto& p : r.contentRe) {
          bool hit = false;
          if (p.literal) {
            hit = head.find(p.text) != std::string::npos;
          } else if (p.re) {
            try { hit = std::regex_search(head, *p.re); } catch (...) {}
          }
          if (hit) {
            out.matched = true;
            out.rule = r;
            out.detail = "content pattern";
            return out;
          }
        }
      }

      if (r.autostartHeuristic && autostart && !autoRule) autoRule = r;
      if (r.elfHeuristic && isElf && !elfRule) elfRule = r;
    }
  }

  MatchResult weak;
  bool cacheable = true;
  if (autoRule) {
    auto v = trust::checkAutostart(path, head);
    if (v.suspicious) {
      weak.matched = true;
      weak.rule = *autoRule;
      weak.detail = "autostart heuristic: " + v.reason;
    }
  }
  if (!weak.matched && elfRule && elfDropSuspicious(path, fd, st, ctx, cacheable)) {
    weak.matched = true;
    weak.rule = *elfRule;
    weak.detail = "elf heuristic";
  }
  if (weak.matched && ctx.pid > 0 &&
      trust::assessActor(ctx.pid).trust == trust::ActorTrust::Trusted) {
    weak = MatchResult{};
    cacheable = false;
  }
  if (weak.matched) {
    weak.heuristic = true;
    return weak;
  }
  out.cacheable = cacheable;
  return out;
}

MatchResult RuleEngine::matchProcess(const std::string& name, const std::string& cmdline, const std::string& exe) {
  MatchResult out;
  std::lock_guard<std::mutex> lock(mu_);
  for (const auto& r : rules_) {
    if (!r.enabled) continue;
    if (!r.nameRe.empty() && anyMatch(r.nameRe, name)) {
      out.matched = true;
      out.rule = r;
      out.detail = "process name";
      return out;
    }
    if (!r.cmdlineRe.empty() && anyMatch(r.cmdlineRe, cmdline)) {
      out.matched = true;
      out.rule = r;
      out.detail = "cmdline pattern";
      return out;
    }
    if (!exe.empty() && !r.pathRe.empty() && anyMatch(r.pathRe, exe)) {
      out.matched = true;
      out.rule = r;
      out.detail = "exe path";
      return out;
    }
  }
  return out;
}

} // namespace oreon
