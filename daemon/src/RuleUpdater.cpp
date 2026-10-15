#include "RuleUpdater.hpp"
#include "Signature.hpp"
#include <oreon/Hash.hpp>
#include <oreon/Paths.hpp>
#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include <filesystem>
#include <algorithm>
#include <regex>

namespace oreon {
namespace fs = std::filesystem;
using json = nlohmann::json;

static constexpr size_t kMaxManifest = 64 * 1024;
static constexpr size_t kMaxRules = 16 * 1024 * 1024;
static constexpr size_t kMaxSig = 1024;

RuleUpdater::~RuleUpdater() { join(); }

void RuleUpdater::join() {
  if (thr_.joinable()) thr_.join();
}

void RuleUpdater::configure(const std::string& baseUrl, const std::string& publicKeyPath,
                            const std::string& feedDir) {
  std::lock_guard<std::mutex> lock(mu_);
  baseUrl_ = baseUrl;
  while (!baseUrl_.empty() && baseUrl_.back() == '/') baseUrl_.pop_back();
  keyPath_ = publicKeyPath;
  feedDir_ = feedDir;
  ensureDir(feedDir_);
  keyPem_.clear();
  readWholeFile(keyPath_, keyPem_, 16 * 1024);
  st_.url = baseUrl_;
  st_.keyPresent = !keyPem_.empty();
  loadState();
}

bool RuleUpdater::verifyBlob(const std::string& yaml, const std::string& sig, std::string* err) const {
  if (keyPem_.empty()) {
    if (err) *err = "rule signing public key missing: " + keyPath_;
    return false;
  }
  return verifyEd25519(keyPem_, yaml, sig, err);
}

void RuleUpdater::loadState() {
  std::string text;
  if (!readWholeFile(feedDir_ + "/state.json", text, kMaxManifest)) return;
  try {
    auto j = json::parse(text);
    st_.lastCheck = j.value("lastCheck", int64_t{0});
    st_.lastUpdate = j.value("lastUpdate", int64_t{0});
    st_.lastResult = j.value("lastResult", "");
    st_.lastError = j.value("lastError", "");
  } catch (...) {}
}

void RuleUpdater::saveState() {
  json j{
    {"lastCheck", st_.lastCheck},
    {"lastUpdate", st_.lastUpdate},
    {"lastResult", st_.lastResult},
    {"lastError", st_.lastError},
    {"version", st_.version}
  };
  writeFileAtomic(feedDir_ + "/state.json", j.dump(2) + "\n");
}

bool RuleUpdater::loadStored(RuleSet& out) {
  std::lock_guard<std::mutex> lock(mu_);
  std::vector<int64_t> versions;
  std::string cur;
  if (readWholeFile(feedDir_ + "/current", cur, 64)) {
    try { versions.push_back(std::stoll(cur)); } catch (...) {}
  }
  std::error_code ec;
  std::vector<int64_t> others;
  static const std::regex re("^rules-([0-9]{1,18})\\.yaml$");
  for (auto& e : fs::directory_iterator(feedDir_, ec)) {
    std::smatch m;
    std::string name = e.path().filename().string();
    if (std::regex_match(name, m, re)) others.push_back(std::stoll(m[1]));
  }
  std::sort(others.rbegin(), others.rend());
  for (auto v : others)
    if (std::find(versions.begin(), versions.end(), v) == versions.end()) versions.push_back(v);

  for (auto v : versions) {
    std::string base = feedDir_ + "/rules-" + std::to_string(v) + ".yaml";
    std::string yaml, sig, err;
    if (!readWholeFile(base, yaml, kMaxRules) || !readWholeFile(base + ".sig", sig, kMaxSig)) continue;
    if (!verifyBlob(yaml, sig, &err)) continue;
    RuleSet rs;
    if (!RuleEngine::parse(yaml, rs, &err)) continue;
    if (rs.version != v) continue;
    st_.version = rs.version;
    st_.published = rs.published;
    out = std::move(rs);
    return true;
  }
  return false;
}

static size_t curlWrite(char* ptr, size_t size, size_t nmemb, void* userdata) {
  auto* ctx = static_cast<std::pair<std::string*, size_t>*>(userdata);
  size_t n = size * nmemb;
  if (ctx->first->size() + n > ctx->second) return 0;
  ctx->first->append(ptr, n);
  return n;
}

bool RuleUpdater::fetch(const std::string& url, std::string& out, size_t maxBytes, std::string* err) {
  static std::once_flag once;
  std::call_once(once, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
  CURL* c = curl_easy_init();
  if (!c) {
    if (err) *err = "curl init failed";
    return false;
  }
  out.clear();
  std::pair<std::string*, size_t> ctx{&out, maxBytes};
  char errbuf[CURL_ERROR_SIZE] = {0};
  curl_easy_setopt(c, CURLOPT_URL, url.c_str());
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curlWrite);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &ctx);
  curl_easy_setopt(c, CURLOPT_ERRORBUFFER, errbuf);
  curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(c, CURLOPT_MAXREDIRS, 3L);
#if LIBCURL_VERSION_NUM >= 0x075500
  curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "https,http");
  curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS_STR, "https");
#endif
  curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L);
  curl_easy_setopt(c, CURLOPT_TIMEOUT, 60L);
  curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(c, CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(c, CURLOPT_USERAGENT, "oreon-defense/" OREON_VERSION);
  CURLcode rc = curl_easy_perform(c);
  curl_easy_cleanup(c);
  if (rc != CURLE_OK) {
    if (err) *err = url + ": " + (errbuf[0] ? errbuf : curl_easy_strerror(rc));
    return false;
  }
  return true;
}

bool RuleUpdater::startAsync(bool force) {
  bool expected = false;
  if (!running_.compare_exchange_strong(expected, true)) return false;
  if (thr_.joinable()) thr_.join();
  thr_ = std::thread([this, force] {
    std::string err;
    updateNow(force, &err);
  });
  return true;
}

bool RuleUpdater::updateNow(bool force, std::string* errOut) {
  running_ = true;
  std::string base, feedDir;
  int64_t current = 0;
  {
    std::lock_guard<std::mutex> lock(mu_);
    base = baseUrl_;
    feedDir = feedDir_;
    current = st_.version;
    st_.running = true;
  }
  bool changed = false;
  std::string err;
  std::string result;
  RuleSet parsed;

  auto finish = [&](bool ok) {
    Status snap;
    {
      std::lock_guard<std::mutex> lock(mu_);
      st_.running = false;
      st_.lastCheck = nowEpoch();
      if (ok) {
        st_.lastError.clear();
        st_.lastResult = result;
        if (changed) {
          st_.lastUpdate = st_.lastCheck;
          st_.version = parsed.version;
          st_.published = parsed.published;
        }
      } else {
        st_.lastError = err;
        st_.lastResult = "failed";
      }
      saveState();
      snap = st_;
    }
    if (changed && rulesCb_) rulesCb_(parsed);
    if (doneCb_) doneCb_(snap, changed);
    if (errOut) *errOut = err;
    running_ = false;
    return changed;
  };

  if (base.empty()) {
    err = "no rules URL configured";
    return finish(false);
  }

  std::string manifestText, yaml, sig;
  if (!fetch(base + "/manifest.json", manifestText, kMaxManifest, &err)) return finish(false);
  int64_t mVersion = 0;
  std::string mSha;
  try {
    auto m = json::parse(manifestText);
    if (m.value("format", 1) != 1) {
      err = "unsupported manifest format";
      return finish(false);
    }
    mVersion = m.value("version", int64_t{0});
    mSha = m.value("sha256", "");
  } catch (const std::exception& e) {
    err = std::string("bad manifest: ") + e.what();
    return finish(false);
  }
  if (mVersion <= 0) {
    err = "manifest has no version";
    return finish(false);
  }
  if (!force && mVersion <= current) {
    result = "up to date (version " + std::to_string(current) + ")";
    return finish(true);
  }

  if (!fetch(base + "/rules.yaml", yaml, kMaxRules, &err)) return finish(false);
  if (!fetch(base + "/rules.yaml.sig", sig, kMaxSig, &err)) return finish(false);

  if (!verifyBlob(yaml, sig, &err)) {
    err = "signature check failed: " + err;
    return finish(false);
  }
  if (!mSha.empty() && sha256String(yaml) != mSha) {
    err = "sha256 does not match manifest";
    return finish(false);
  }
  std::string perr;
  if (!RuleEngine::parse(yaml, parsed, &perr)) {
    err = "rules do not parse: " + perr;
    return finish(false);
  }
  if (parsed.version != mVersion) {
    err = "rules version " + std::to_string(parsed.version) +
          " does not match manifest " + std::to_string(mVersion);
    return finish(false);
  }
  if (parsed.version < current) {
    err = "refusing older rules (version " + std::to_string(parsed.version) +
          " < " + std::to_string(current) + ")";
    return finish(false);
  }
  if (parsed.version == current) {
    result = "up to date (version " + std::to_string(current) + ")";
    return finish(true);
  }

  std::string vname = feedDir + "/rules-" + std::to_string(parsed.version) + ".yaml";
  if (!writeFileAtomic(vname + ".sig", sig) || !writeFileAtomic(vname, yaml) ||
      !writeFileAtomic(feedDir + "/current", std::to_string(parsed.version) + "\n")) {
    err = "cannot write rules to " + feedDir;
    return finish(false);
  }
  std::error_code ec;
  static const std::regex re("^rules-([0-9]{1,18})\\.yaml(\\.sig)?$");
  for (auto& e : fs::directory_iterator(feedDir, ec)) {
    std::smatch m;
    std::string name = e.path().filename().string();
    if (!std::regex_match(name, m, re)) continue;
    int64_t v = std::stoll(m[1]);
    if (v != parsed.version && v != current) fs::remove(e.path(), ec);
  }
  changed = true;
  result = "updated to version " + std::to_string(parsed.version);
  return finish(true);
}

RuleUpdater::Status RuleUpdater::status() const {
  std::lock_guard<std::mutex> lock(mu_);
  Status s = st_;
  s.running = running_;
  return s;
}

}
