#pragma once
#include <nlohmann/json.hpp>
#include "Types.hpp"

namespace oreon {

using json = nlohmann::json;

inline json threatToJson(const Threat& t) {
  return json{
    {"id", t.id},
    {"name", t.name},
    {"path", t.path},
    {"ruleId", t.ruleId},
    {"description", t.description},
    {"severity", severityToString(t.severity)},
    {"sha256", t.sha256},
    {"timestamp", t.timestamp},
    {"action", static_cast<int>(t.action)},
    {"quarantineId", t.quarantineId}
  };
}

inline Threat threatFromJson(const json& j) {
  Threat t;
  t.id = j.value("id", "");
  t.name = j.value("name", "");
  t.path = j.value("path", "");
  t.ruleId = j.value("ruleId", "");
  t.description = j.value("description", "");
  t.severity = severityFromString(j.value("severity", "medium"));
  t.sha256 = j.value("sha256", "");
  t.timestamp = j.value("timestamp", int64_t{0});
  t.action = static_cast<ThreatAction>(j.value("action", 0));
  t.quarantineId = j.value("quarantineId", "");
  return t;
}

inline json protectionToJson(const ProtectionState& p) {
  return json{
    {"fileRealtime", p.fileRealtime},
    {"processWatch", p.processWatch},
    {"networkWatch", p.networkWatch},
    {"protected", p.protectedStatus},
    {"statusText", p.statusText},
    {"lastScan", p.lastScan},
    {"threatCount", p.threatCount},
    {"quarantineCount", p.quarantineCount}
  };
}

inline json logToJson(const LogEvent& e) {
  return json{
    {"id", e.id},
    {"timestamp", e.timestamp},
    {"category", e.category},
    {"severity", severityToString(e.severity)},
    {"message", e.message},
    {"path", e.path}
  };
}

inline json quarantineToJson(const QuarantineItem& q) {
  return json{
    {"id", q.id},
    {"originalPath", q.originalPath},
    {"threatName", q.threatName},
    {"sha256", q.sha256},
    {"severity", severityToString(q.severity)},
    {"quarantinedAt", q.quarantinedAt},
    {"metaPath", q.metaPath},
    {"dataPath", q.dataPath}
  };
}

} // namespace oreon
