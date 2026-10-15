#pragma once
#include <oreon/Types.hpp>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <algorithm>
#include <cctype>

namespace oreon {
namespace guard {

enum class ExecDecision { Allow, Alert, Block };

struct ExecInputs {
  bool inDevShm{false};
  bool inTemp{false};
  bool inDownloads{false};
  bool packageOwned{false};
  bool trustedWriter{false};
  bool allowListed{false};
  bool appImage{false};
};

inline ExecDecision execDecision(const ExecInputs& in) {
  if (in.packageOwned || in.trustedWriter || in.allowListed) return ExecDecision::Allow;
  if (in.inDevShm) return ExecDecision::Block;
  if (in.inTemp || in.inDownloads) return ExecDecision::Alert;
  return ExecDecision::Alert;
}

inline std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
  return s;
}

inline bool looksLikeRansomName(const std::string& path) {
  std::string p = lower(path);
  static const char* exts[] = {".locked", ".crypt", ".crypted", ".encrypted",
    ".enc", ".cerber", ".locky", ".wncry", ".wcry", ".ryk", ".ryuk",
    ".conti", ".lockbit", ".crinf", ".r5a", ".xtbl", ".payransom"};
  for (auto e : exts) {
    size_t n = std::string(e).size();
    if (p.size() > n && p.compare(p.size() - n, n, e) == 0) return true;
  }
  static const char* notes[] = {"readme_to_decrypt", "how_to_decrypt",
    "decrypt_instruction", "your_files_are_encrypted", "restore_files",
    "how_to_back_files", "recover_your_files", "!!!readme!!!"};
  std::string base = p;
  auto slash = base.find_last_of('/');
  if (slash != std::string::npos) base = base.substr(slash + 1);
  for (auto nte : notes)
    if (base.find(nte) != std::string::npos) return true;
  return false;
}

class RansomTracker {
public:
  struct Config {
    int windowMs{3000};
    int burstCount{40};
    int ransomNameHits{3};
  };

  RansomTracker() {}
  explicit RansomTracker(const Config& c) : cfg_(c) {}

  bool record(const std::string& path, const std::string& op, int64_t nowMs) {
    std::lock_guard<std::mutex> lk(mu_);
    while (!events_.empty() && nowMs - events_.front() > cfg_.windowMs) events_.pop_front();
    events_.push_back(nowMs);
    if (looksLikeRansomName(path)) ++ransomHits_;
    (void)op;
    bool fire = static_cast<int>(events_.size()) >= cfg_.burstCount ||
                ransomHits_ >= cfg_.ransomNameHits;
    if (fire) { events_.clear(); ransomHits_ = 0; }
    return fire;
  }

  void reset() {
    std::lock_guard<std::mutex> lk(mu_);
    events_.clear();
    ransomHits_ = 0;
  }

private:
  Config cfg_;
  std::mutex mu_;
  std::deque<int64_t> events_;
  int ransomHits_{0};
};

struct PersistDiff {
  int added{0};
  int removed{0};
  std::string firstAdded;
  std::string firstRemoved;
  bool changed() const { return added > 0 || removed > 0; }
  std::string summary() const {
    std::string s;
    if (added) s += std::to_string(added) + " line(s) added";
    if (removed) { if (!s.empty()) s += ", "; s += std::to_string(removed) + " line(s) removed"; }
    if (!firstAdded.empty()) s += "; added: " + firstAdded;
    return s;
  }
};

inline std::vector<std::string> splitLines(const std::string& t) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : t) {
    if (c == '\n') { out.push_back(cur); cur.clear(); }
    else cur += c;
  }
  if (!cur.empty()) out.push_back(cur);
  return out;
}

inline PersistDiff persistenceDiff(const std::string& oldText, const std::string& newText) {
  auto a = splitLines(oldText), b = splitLines(newText);
  PersistDiff d;
  for (const auto& line : b) {
    if (std::find(a.begin(), a.end(), line) == a.end()) {
      ++d.added;
      if (d.firstAdded.empty() && !line.empty()) d.firstAdded = line.substr(0, 120);
    }
  }
  for (const auto& line : a) {
    if (std::find(b.begin(), b.end(), line) == b.end()) {
      ++d.removed;
      if (d.firstRemoved.empty() && !line.empty()) d.firstRemoved = line.substr(0, 120);
    }
  }
  return d;
}

}
}
