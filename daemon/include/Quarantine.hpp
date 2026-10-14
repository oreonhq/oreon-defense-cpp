#pragma once
#include <oreon/Types.hpp>
#include <string>
#include <vector>
#include <mutex>
#include <optional>

namespace oreon {

class Quarantine {
public:
  void setDir(const std::string& dir);
  std::optional<QuarantineItem> quarantineFile(const std::string& path, const Threat& threat);
  bool restore(const std::string& id, std::string* err = nullptr);
  bool remove(const std::string& id, std::string* err = nullptr);
  std::vector<QuarantineItem> list() const;
  std::optional<QuarantineItem> get(const std::string& id) const;
  void reload();

private:
  mutable std::mutex mu_;
  std::string dir_;
  std::vector<QuarantineItem> items_;
  void saveMeta(const QuarantineItem& item) const;
};

} // namespace oreon
