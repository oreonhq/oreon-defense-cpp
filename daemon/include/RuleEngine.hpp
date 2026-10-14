#pragma once
#include <oreon/Types.hpp>
#include <string>
#include <vector>
#include <regex>
#include <optional>
#include <mutex>

namespace oreon {

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
  bool enabled{true};
};

struct MatchResult {
  bool matched{false};
  Rule rule;
  std::string detail;
};

class RuleEngine {
public:
  bool loadFile(const std::string& path);
  bool loadYaml(const std::string& yamlText);
  size_t ruleCount() const;
  MatchResult matchFile(const std::string& path, const std::string& sha256 = "");
  MatchResult matchProcess(const std::string& name, const std::string& cmdline, const std::string& exe);
  std::vector<Rule> rules() const;
  void addAllowPath(const std::string& path);
  bool isAllowed(const std::string& path) const;

private:
  mutable std::mutex mu_;
  std::vector<Rule> rules_;
  std::vector<std::string> allowPaths_;
  bool looksLikeElf(const std::string& path) const;
  bool pathMatches(const Rule& r, const std::string& path) const;
  bool contentMatches(const Rule& r, const std::string& path) const;
};

} // namespace oreon
