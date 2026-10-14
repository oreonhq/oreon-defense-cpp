#pragma once
#include <oreon/Types.hpp>
#include <oreon/Paths.hpp>
#include <string>

namespace oreon {

class Config {
public:
  bool load(const std::string& path = "");
  bool save(const std::string& path = "") const;
  DaemonConfig& get() { return cfg_; }
  const DaemonConfig& get() const { return cfg_; }
  void applyDefaults();

private:
  DaemonConfig cfg_;
  std::string path_;
};

} // namespace oreon
