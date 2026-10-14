#include "RuleEngine.hpp"
#include <oreon/Hash.hpp>
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cstring>

namespace oreon {

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
  try {
    YAML::Node root = YAML::Load(yamlText);
    std::vector<Rule> loaded;
    auto rulesNode = root["rules"];
    if (!rulesNode || !rulesNode.IsSequence()) return false;
    for (const auto& n : rulesNode) {
      Rule r;
      r.id = n["id"].as<std::string>("");
      r.name = n["name"].as<std::string>("");
      r.description = n["description"].as<std::string>("");
      r.severity = severityFromString(n["severity"].as<std::string>("medium"));
      r.enabled = n["enabled"].as<bool>(true);
      r.elfHeuristic = n["elf_heuristic"].as<bool>(false);
      if (n["hashes"])
        for (const auto& h : n["hashes"]) r.hashes.push_back(h.as<std::string>());
      if (n["path_patterns"])
        for (const auto& p : n["path_patterns"]) r.pathPatterns.push_back(p.as<std::string>());
      if (n["cmdline_patterns"])
        for (const auto& p : n["cmdline_patterns"]) r.cmdlinePatterns.push_back(p.as<std::string>());
      if (n["name_patterns"])
        for (const auto& p : n["name_patterns"]) r.namePatterns.push_back(p.as<std::string>());
      if (n["content_patterns"])
        for (const auto& p : n["content_patterns"]) r.contentPatterns.push_back(p.as<std::string>());
      if (!r.id.empty()) loaded.push_back(std::move(r));
    }
    std::lock_guard<std::mutex> lock(mu_);
    rules_ = std::move(loaded);
    return true;
  } catch (const std::exception& e) {
    std::cerr << "rules parse error: " << e.what() << "\n";
    return false;
  }
}

size_t RuleEngine::ruleCount() const {
  std::lock_guard<std::mutex> lock(mu_);
  return rules_.size();
}

std::vector<Rule> RuleEngine::rules() const {
  std::lock_guard<std::mutex> lock(mu_);
  return rules_;
}

void RuleEngine::addAllowPath(const std::string& path) {
  std::lock_guard<std::mutex> lock(mu_);
  allowPaths_.push_back(path);
}

bool RuleEngine::isAllowed(const std::string& path) const {
  std::lock_guard<std::mutex> lock(mu_);
  for (const auto& a : allowPaths_) {
    if (path == a || path.find(a) == 0) return true;
  }
  return false;
}

bool RuleEngine::pathMatches(const Rule& r, const std::string& path) const {
  for (const auto& pat : r.pathPatterns) {
    try {
      if (std::regex_search(path, std::regex(pat, std::regex::icase))) return true;
    } catch (...) {
      if (path.find(pat) != std::string::npos) return true;
    }
  }
  return false;
}

bool RuleEngine::looksLikeElf(const std::string& path) const {
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  char magic[4] = {};
  in.read(magic, 4);
  return in.gcount() == 4 && magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
}

bool RuleEngine::contentMatches(const Rule& r, const std::string& path) const {
  if (r.contentPatterns.empty()) return false;
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  // read up to 1mb
  std::string buf(1024 * 1024, '\0');
  in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
  buf.resize(static_cast<size_t>(in.gcount()));
  for (const auto& pat : r.contentPatterns) {
    try {
      if (std::regex_search(buf, std::regex(pat))) return true;
    } catch (...) {
      if (buf.find(pat) != std::string::npos) return true;
    }
  }
  return false;
}

MatchResult RuleEngine::matchFile(const std::string& path, const std::string& sha256In) {
  MatchResult out;
  if (isAllowed(path)) return out;

  std::string hash = sha256In;
  if (hash.empty()) hash = sha256File(path);

  std::lock_guard<std::mutex> lock(mu_);
  for (const auto& r : rules_) {
    if (!r.enabled) continue;

    if (!r.hashes.empty() && !hash.empty()) {
      for (const auto& h : r.hashes) {
        if (strcasecmp(h.c_str(), hash.c_str()) == 0) {
          out.matched = true;
          out.rule = r;
          out.detail = "hash match";
          return out;
        }
      }
    }

    if (pathMatches(r, path)) {
      out.matched = true;
      out.rule = r;
      out.detail = "path pattern";
      return out;
    }

    if (!r.contentPatterns.empty() && contentMatches(r, path)) {
      out.matched = true;
      out.rule = r;
      out.detail = "content pattern";
      return out;
    }

    if (r.elfHeuristic) {
      // hidden elf in downloads/tmp with suspicious name
      std::string base = path.substr(path.find_last_of('/') + 1);
      bool inHot = path.find("/Downloads") != std::string::npos ||
                   path.find("/tmp/") != std::string::npos ||
                   path.find("/Desktop") != std::string::npos;
      bool weirdName = base.find('.') == std::string::npos ||
                       base.find("update") != std::string::npos ||
                       base.find("payload") != std::string::npos ||
                       base.find("miner") != std::string::npos;
      if (inHot && weirdName && looksLikeElf(path)) {
        out.matched = true;
        out.rule = r;
        out.detail = "elf heuristic";
        return out;
      }
    }
  }
  return out;
}

MatchResult RuleEngine::matchProcess(const std::string& name, const std::string& cmdline, const std::string& exe) {
  MatchResult out;
  std::lock_guard<std::mutex> lock(mu_);
  for (const auto& r : rules_) {
    if (!r.enabled) continue;
    for (const auto& pat : r.namePatterns) {
      try {
        if (std::regex_search(name, std::regex(pat, std::regex::icase))) {
          out.matched = true;
          out.rule = r;
          out.detail = "process name";
          return out;
        }
      } catch (...) {}
    }
    for (const auto& pat : r.cmdlinePatterns) {
      try {
        if (std::regex_search(cmdline, std::regex(pat, std::regex::icase))) {
          out.matched = true;
          out.rule = r;
          out.detail = "cmdline pattern";
          return out;
        }
      } catch (...) {}
    }
    if (pathMatches(r, exe)) {
      out.matched = true;
      out.rule = r;
      out.detail = "exe path";
      return out;
    }
  }
  return out;
}

} // namespace oreon
