#pragma once
// line-delimited json over unix socket
// request:  {"id":"1","method":"...","params":{...}}
// response: {"id":"1","ok":true,"result":{...}}
// event:    {"event":"threat","data":{...}}

namespace oreon {
namespace proto {
  constexpr const char* MethodGetStatus = "getStatus";
  constexpr const char* MethodSetProtection = "setProtection";
  constexpr const char* MethodStartScan = "startScan";
  constexpr const char* MethodCancelScan = "cancelScan";
  constexpr const char* MethodGetScanProgress = "getScanProgress";
  constexpr const char* MethodGetThreats = "getThreats";
  constexpr const char* MethodGetQuarantine = "getQuarantine";
  constexpr const char* MethodQuarantine = "quarantine";
  constexpr const char* MethodRestore = "restore";
  constexpr const char* MethodDeleteQuarantine = "deleteQuarantine";
  constexpr const char* MethodAllow = "allow";
  constexpr const char* MethodGetNetwork = "getNetwork";
  constexpr const char* MethodGetHistory = "getHistory";
  constexpr const char* MethodGetConfig = "getConfig";
  constexpr const char* MethodSetConfig = "setConfig";
  constexpr const char* MethodUpdateRules = "updateRules";
  constexpr const char* MethodPing = "ping";
  constexpr const char* MethodGetEngineStatus = "getEngineStatus";
  constexpr const char* MethodSetOptions = "setOptions";
  constexpr const char* MethodGetBlocklist = "getBlocklist";
  constexpr const char* MethodBlockIp = "blockIp";
  constexpr const char* MethodUnblockIp = "unblockIp";
  constexpr const char* MethodKillProcess = "killProcess";
  constexpr const char* MethodWhoAmI = "whoami";

  constexpr const char* EventThreat = "threat";
  constexpr const char* EventScanProgress = "scanProgress";
  constexpr const char* EventScanDone = "scanDone";
  constexpr const char* EventStatus = "status";
  constexpr const char* EventLog = "log";
  constexpr const char* EventProcess = "process";
  constexpr const char* EventNetwork = "network";
  constexpr const char* EventEngine = "engine";
  constexpr const char* EventRulesUpdate = "rulesUpdate";
  constexpr const char* EventBlocklist = "blocklist";
}
}
