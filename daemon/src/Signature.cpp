#include "Signature.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <fstream>
#include <vector>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace oreon {

static std::string decodeSig(const std::string& sig) {
  if (sig.size() == 64) return sig;
  std::string s;
  for (char c : sig)
    if (!isspace(static_cast<unsigned char>(c))) s.push_back(c);
  if (s.empty() || s.size() > 200) return {};
  std::vector<unsigned char> out(s.size());
  int n = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(s.data()),
                          static_cast<int>(s.size()));
  if (n < 0) return {};
  size_t pad = 0;
  if (!s.empty() && s.back() == '=') ++pad;
  if (s.size() > 1 && s[s.size() - 2] == '=') ++pad;
  size_t len = static_cast<size_t>(n) - pad;
  return std::string(reinterpret_cast<char*>(out.data()), len);
}

bool verifyEd25519(const std::string& publicKeyPem, const std::string& data,
                   const std::string& signature, std::string* err) {
  std::string sig = decodeSig(signature);
  if (sig.size() != 64) {
    if (err) *err = "signature is not 64 bytes";
    return false;
  }
  BIO* bio = BIO_new_mem_buf(publicKeyPem.data(), static_cast<int>(publicKeyPem.size()));
  if (!bio) {
    if (err) *err = "BIO_new_mem_buf failed";
    return false;
  }
  EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!key) {
    if (err) *err = "cannot parse public key";
    return false;
  }
  if (EVP_PKEY_id(key) != EVP_PKEY_ED25519) {
    EVP_PKEY_free(key);
    if (err) *err = "public key is not Ed25519";
    return false;
  }
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  bool ok = ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) == 1 &&
            EVP_DigestVerify(ctx, reinterpret_cast<const unsigned char*>(sig.data()), sig.size(),
                             reinterpret_cast<const unsigned char*>(data.data()), data.size()) == 1;
  if (ctx) EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  ERR_clear_error();
  if (!ok && err) *err = "signature does not match";
  return ok;
}

bool readWholeFile(const std::string& path, std::string& out, size_t maxBytes) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  out.clear();
  char buf[65536];
  while (in) {
    in.read(buf, sizeof(buf));
    out.append(buf, static_cast<size_t>(in.gcount()));
    if (out.size() > maxBytes) return false;
  }
  return true;
}

bool writeFileAtomic(const std::string& path, const std::string& data, unsigned mode) {
  std::string tmp = path + ".tmp";
  int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, mode);
  if (fd < 0) return false;
  const char* p = data.data();
  size_t left = data.size();
  while (left > 0) {
    ssize_t n = write(fd, p, left);
    if (n <= 0) {
      close(fd);
      unlink(tmp.c_str());
      return false;
    }
    p += n;
    left -= static_cast<size_t>(n);
  }
  fsync(fd);
  close(fd);
  if (rename(tmp.c_str(), path.c_str()) != 0) {
    unlink(tmp.c_str());
    return false;
  }
  return true;
}

}
