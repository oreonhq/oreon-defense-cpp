#pragma once
#include <string>
#include <vector>

namespace oreon {
namespace heuristics {

struct Hit {
  bool matched{false};
  std::string pattern;
};

Hit strongProcessPattern(const std::vector<std::string>& argv, const std::string& exe);

std::string inlineCode(const std::vector<std::string>& argv, const std::string& exe);

}
}
