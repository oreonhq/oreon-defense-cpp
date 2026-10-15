#include "RuleEngine.hpp"
#include "Signature.hpp"
#include "NetBlocker.hpp"
#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <iomanip>
#include <sstream>

static int failures = 0;

static std::string sha256Hex(const std::string& data) {
  unsigned char h[EVP_MAX_MD_SIZE];
  unsigned len = 0;
  EVP_Digest(data.data(), data.size(), h, &len, EVP_sha256(), nullptr);
  std::ostringstream o;
  for (unsigned i = 0; i < len; ++i) o << std::hex << std::setw(2) << std::setfill('0') << int(h[i]);
  return o.str();
}

static bool signWithTempKey(const std::string& data, std::string& pem, std::string& sig) {
  EVP_PKEY* key = nullptr;
  EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  bool ok = kctx && EVP_PKEY_keygen_init(kctx) == 1 && EVP_PKEY_keygen(kctx, &key) == 1;
  EVP_PKEY_CTX_free(kctx);
  if (!ok) return false;
  EVP_MD_CTX* md = EVP_MD_CTX_new();
  unsigned char raw[64];
  size_t rawLen = sizeof(raw);
  ok = md && EVP_DigestSignInit(md, nullptr, nullptr, nullptr, key) == 1 &&
       EVP_DigestSign(md, raw, &rawLen, reinterpret_cast<const unsigned char*>(data.data()), data.size()) == 1;
  EVP_MD_CTX_free(md);
  if (ok) {
    sig.assign(reinterpret_cast<char*>(raw), rawLen);
    BIO* bio = BIO_new(BIO_s_mem());
    ok = bio && PEM_write_bio_PUBKEY(bio, key) == 1;
    if (ok) {
      char* p = nullptr;
      long n = BIO_get_mem_data(bio, &p);
      pem.assign(p, static_cast<size_t>(n));
    }
    BIO_free(bio);
  }
  EVP_PKEY_free(key);
  return ok;
}
#define CHECK(cond, msg) do { if (!(cond)) { std::cerr << "FAIL: " << msg << "\n"; ++failures; } \
                              else std::cout << "ok: " << msg << "\n"; } while (0)

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cerr << "usage: test_feed PUBKEY.pem FEED_DIR\n";
    return 2;
  }
  std::string pem, yaml, sig;
  CHECK(oreon::readWholeFile(argv[1], pem), "read public key");
  std::string dir = argv[2];
  CHECK(oreon::readWholeFile(dir + "/rules.yaml", yaml), "read rules.yaml");
  CHECK(oreon::readWholeFile(dir + "/rules.yaml.sig", sig), "read rules.yaml.sig");

  std::string err, manifest;
  CHECK(oreon::readWholeFile(dir + "/manifest.json", manifest), "read manifest.json");

  std::string tmpPem, tmpSig;
  CHECK(signWithTempKey(yaml, tmpPem, tmpSig), "sign with a throwaway key");
  CHECK(oreon::verifyEd25519(tmpPem, yaml, tmpSig, &err), "signature verifies " + err);
  std::string tampered = yaml + "\n# extra\n";
  CHECK(!oreon::verifyEd25519(tmpPem, tampered, tmpSig, &err), "tampered rules rejected");
  std::string badSig = tmpSig;
  badSig[0] ^= 1;
  CHECK(!oreon::verifyEd25519(tmpPem, yaml, badSig, &err), "flipped signature rejected");
  CHECK(!oreon::verifyEd25519("not a key", yaml, tmpSig, &err), "garbage key rejected");
  CHECK(!oreon::verifyEd25519(pem, yaml, tmpSig, &err), "signature from another key rejected");

  bool signedCurrent = manifest.find("\"" + sha256Hex(yaml) + "\"") != std::string::npos;
  if (signedCurrent) {
    CHECK(oreon::verifyEd25519(pem, yaml, sig, &err), "published signature verifies " + err);
  } else {
    std::cout << "note: rules-feed/rules.yaml changed since it was signed, re-sign it with "
                 "scripts/sign-rules.sh sign KEY rules-feed/rules.yaml rules-feed\n";
    CHECK(!oreon::verifyEd25519(pem, yaml, sig, &err), "stale published signature is refused");
  }

  oreon::RuleSet rs;
  CHECK(oreon::RuleEngine::parse(yaml, rs, &err), "feed parses");
  CHECK(rs.version == 2026100301, "feed version read");
  CHECK(rs.rules.size() >= 6, "feed has the starter rules");
  CHECK(rs.blocklist.size() == 4, "feed has 4 blocklist entries");

  bool pipeKill = true, minerKill = false;
  for (const auto& r : rs.rules) {
    if (r.id == "pipe-exec") pipeKill = r.kill;
    if (r.id == "fake-xmrig") minerKill = r.kill;
  }
  CHECK(!pipeKill, "pipe-exec is alert only");
  CHECK(minerKill, "fake-xmrig kills");

  bool elfLow = false, autoOk = false;
  for (const auto& r : rs.rules) {
    if (r.id == "tmp-elf-heuristic") elfLow = r.elfHeuristic && r.severity == oreon::Severity::Low;
    if (r.id == "persistence-autostart")
      autoOk = r.autostartHeuristic && r.pathPatterns.empty() && r.severity == oreon::Severity::Low &&
               !r.kill;
  }
  CHECK(elfLow, "tmp-elf-heuristic is low severity");
  CHECK(autoOk, "persistence-autostart uses the content check, not a path pattern");

  oreon::RuleSet older;
  older.version = 1;
  auto merged = oreon::RuleEngine::merge({older, rs});
  CHECK(merged.version == rs.version, "merge keeps newest version");

  oreon::RuleSet bad;
  CHECK(!oreon::RuleEngine::parse("version: 3\nrules: nope\n", bad, &err), "bad rules rejected");

  oreon::RuleEngine eng;
  eng.setRuleSet(rs);
  auto m = eng.matchProcess("bash", "bash -c curl http://x | sh", "/usr/bin/bash");
  CHECK(m.matched && m.rule.id == "pipe-exec", "cmdline regex matches");

  std::string out;
  bool v6 = false;
  CHECK(oreon::NetBlocker::normalize("198.51.100.7/24", out, v6, &err) && out == "198.51.100.0/24" && !v6,
        "v4 cidr normalized");
  CHECK(oreon::NetBlocker::normalize("203.0.113.13", out, v6, &err) && out == "203.0.113.13", "v4 host");
  CHECK(oreon::NetBlocker::normalize("2001:db8:dead:beef::1/64", out, v6, &err) &&
        out == "2001:db8:dead:beef::/64" && v6, "v6 cidr normalized");
  CHECK(!oreon::NetBlocker::normalize("127.0.0.1", out, v6, &err), "loopback refused");
  CHECK(!oreon::NetBlocker::normalize("0.0.0.0/0", out, v6, &err), "default route refused");
  CHECK(!oreon::NetBlocker::normalize("10.0.0.0/4", out, v6, &err), "too wide refused");
  CHECK(!oreon::NetBlocker::normalize("::1", out, v6, &err), "v6 loopback refused");
  CHECK(!oreon::NetBlocker::normalize("1.2.3.4; flush ruleset", out, v6, &err), "injection refused");
  CHECK(!oreon::NetBlocker::normalize("example.com", out, v6, &err), "hostname refused");
  CHECK(!oreon::NetBlocker::normalize("224.0.0.1", out, v6, &err), "multicast refused");

  oreon::NetBlocker nb;
  nb.setFeed({{"198.51.100.0/24", "t"}});
  CHECK(nb.isBlocked("198.51.100.200"), "ip inside blocked range");
  CHECK(!nb.isBlocked("198.51.101.1"), "ip outside range");

  if (failures) {
    std::cerr << failures << " failures\n";
    return 1;
  }
  std::cout << "test_feed: ok\n";
  return 0;
}
