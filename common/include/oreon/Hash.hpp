#pragma once
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace oreon {

inline std::string sha256File(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return {};
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return {};
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    return {};
  }
  char buf[8192];
  while (in) {
    in.read(buf, sizeof(buf));
    auto n = in.gcount();
    if (n > 0) {
      if (EVP_DigestUpdate(ctx, buf, static_cast<size_t>(n)) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
      }
    }
  }
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  if (EVP_DigestFinal_ex(ctx, hash, &len) != 1) {
    EVP_MD_CTX_free(ctx);
    return {};
  }
  EVP_MD_CTX_free(ctx);
  std::ostringstream oss;
  for (unsigned int i = 0; i < len; ++i)
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
  return oss.str();
}

inline std::string sha256Bytes(const void* data, size_t len) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(static_cast<const unsigned char*>(data), len, hash);
  std::ostringstream oss;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
  return oss.str();
}

inline std::string sha256String(const std::string& s) {
  return sha256Bytes(s.data(), s.size());
}

} // namespace oreon
