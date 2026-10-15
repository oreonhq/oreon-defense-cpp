#pragma once
#include <string>

namespace oreon {

bool verifyEd25519(const std::string& publicKeyPem, const std::string& data,
                   const std::string& signature, std::string* err = nullptr);

bool readWholeFile(const std::string& path, std::string& out, size_t maxBytes = 64 * 1024 * 1024);
bool writeFileAtomic(const std::string& path, const std::string& data, unsigned mode = 0644);

}
