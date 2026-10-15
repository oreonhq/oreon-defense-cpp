#pragma once
#include <oreon/Types.hpp>
#include <string>
#include <vector>
#include <regex>
#include <optional>
#include <mutex>
#include <memory>
#include <sys/types.h>
#include <sys/stat.h>

namespace oreon {

struct Pattern {
  std::string text;
  bool literal{true};
  std::shared_ptr<std::regex> re;
};

struct Rule {
  std::string id;
  std::string name;
  std::string description;
  Severity severity{Severity::Medium};
  std::vector<std::string> hashes;      // sha256
  std::vector<std::string> pathPatterns;
  std::vector<std::string> cmdlinePatterns;
  std::vector<std::string> namePatterns;
  std::vector<std::string> contentPatterns; // simple substring / regex
  bool elfHeuristic{false};
  bool autostartHeuristic{false};
  bool enabled{true};
  bool kill{false};
  bool killCmdline{false};

  std::vector<Pattern> pathRe, cmdlineRe, nameRe, contentRe;
};

struct BlockEntry {
  std::string cidr;
  std::string reason;
};

struct RuleSet {
  int64_t version{0};
  std::string published;
  std::vector<Rule> rules;
  std::vector<BlockEntry> blocklist;
};

struct MatchResult {
  bool matched{false};
  Rule rule;
  std::string detail;
  bool heuristic{false};
  bool cacheable{true};
};

struct ScanContext {
  pid_t pid{0};
  bool exec{false};
};

class RuleEngine {
public:
  static bool parse(const std::string& yamlText, RuleSet& out, std::string* err = nullptr);
  static RuleSet merge(const std::vector<RuleSet>& sets);

  bool loadFile(const std::string& path);
  bool loadYaml(const std::string& yamlText);
  void setRuleSet(RuleSet rs);
  size_t ruleCount() const;
  int64_t version() const;
  std::vector<BlockEntry> blocklist() const;

  MatchResult matchFile(const std::string& path, const std::string& sha256 = "");
  MatchResult matchFd(int fd, const std::string& path, const ScanContext& ctx = {});
  MatchResult matchProcess(const std::string& name, const std::string& cmdline, const std::string& exe);
  std::vector<Rule> rules() const;
  void addAllowPath(const std::string& path);
  bool isAllowed(const std::string& path) const;
  bool needsHash() const;

private:
  MatchResult matchData(const std::string& path, const std::string& hash,
                        const std::string& head, bool isElf, int fd,
                        const struct stat* st, const ScanContext& ctx) const;
  static bool anyMatch(const std::vector<Pattern>& pats, const std::string& s);

  mutable std::mutex mu_;
  std::vector<Rule> rules_;
  int64_t version_{0};
  std::vector<BlockEntry> blocklist_;
  std::vector<std::string> allowPaths_;
};

} // namespace oreon
