#pragma once
#include <oreon/Types.hpp>
#include <string>

namespace oreon {

struct Detection {
  bool matched{false};
  std::string name;
  std::string ruleId;
  std::string detail;
  std::string engine;
  std::string description;
  Severity severity{Severity::High};
  bool kill{true};
  bool heuristic{false};
  bool cacheable{true};
};

}
