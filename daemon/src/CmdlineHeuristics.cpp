#include "CmdlineHeuristics.hpp"
#include <regex>

namespace oreon {
namespace heuristics {
namespace {

std::string base(const std::string& p) {
  auto s = p.find_last_of('/');
  return s == std::string::npos ? p : p.substr(s + 1);
}

bool shellName(const std::string& b) {
  for (const char* n : {"sh", "bash", "dash", "zsh", "ksh", "mksh", "fish", "ash", "busybox"})
    if (b == n) return true;
  return false;
}

bool pythonName(const std::string& b) { return b.rfind("python", 0) == 0; }

bool scriptName(const std::string& b) {
  return b == "perl" || b.rfind("perl5", 0) == 0 || b == "ruby" || b == "node" || b == "php" ||
         b == "lua" || b.rfind("lua5", 0) == 0;
}

bool shortCluster(const std::string& a, char c) {
  return a.size() >= 2 && a[0] == '-' && a[1] != '-' && a.find(c, 1) != std::string::npos;
}

bool netTool(const std::string& b) { return b == "nc" || b == "ncat" || b == "netcat"; }

bool shellCodeBad(const std::string& code, std::string& why) {
  if (code.find("/dev/tcp/") != std::string::npos) { why = "/dev/tcp/"; return true; }
  if (code.find("/dev/udp/") != std::string::npos) { why = "/dev/udp/"; return true; }
  static const std::regex ncExec(R"((^|[\s;|&(`])(nc|ncat|netcat)(\s+\S+)*\s+-[a-zA-Z]*[ec](\s|$))");
  if (std::regex_search(code, ncExec)) { why = "nc -e"; return true; }
  static const std::regex fifo(R"(\bmkfifo\b[\s\S]*\b(nc|ncat|netcat|telnet|openssl\s+s_client|socat)\b)");
  if (std::regex_search(code, fifo)) { why = "mkfifo"; return true; }
  static const std::regex socatExec(R"(\bsocat\b[^;|&]*\b(exec|system):)", std::regex::icase);
  if (std::regex_search(code, socatExec)) { why = "socat exec"; return true; }
  static const std::regex iShell(R"(\b(ba)?sh\s+-i\b[^;|]*>&)");
  if (std::regex_search(code, iShell)) { why = "sh -i"; return true; }
  return false;
}

bool scriptCodeBad(const std::string& code, std::string& why) {
  if (code.find("pty.spawn") != std::string::npos) { why = "pty.spawn"; return true; }
  if (code.find("import pty") != std::string::npos) { why = "import pty"; return true; }
  const bool sock = code.find("socket") != std::string::npos;
  if (sock && (code.find("dup2") != std::string::npos || code.find("subprocess") != std::string::npos ||
               code.find("/bin/sh") != std::string::npos || code.find("/bin/bash") != std::string::npos ||
               code.find("exec(") != std::string::npos || code.find("system(") != std::string::npos)) {
    why = "import socket";
    return true;
  }
  return shellCodeBad(code, why);
}

}

std::string inlineCode(const std::vector<std::string>& argv, const std::string& exe) {
  const std::string b = base(exe);
  const bool sh = shellName(b), py = pythonName(b), sc = scriptName(b);
  if (!sh && !py && !sc) return {};
  for (size_t i = 1; i < argv.size(); ++i) {
    const std::string& a = argv[i];
    if (a == "--") break;
    if (a.empty() || a[0] != '-') {
      if (sh && (a == "-o" || a == "+o")) continue;
      break;
    }
    if (sh && shortCluster(a, 'c')) return i + 1 < argv.size() ? argv[i + 1] : std::string();
    if (py && shortCluster(a, 'c')) return i + 1 < argv.size() ? argv[i + 1] : std::string();
    if (sc && (a == "-e" || a == "-E" || a == "--eval" || a == "-p" || shortCluster(a, 'e')))
      return i + 1 < argv.size() ? argv[i + 1] : std::string();
    if (sh && (a == "-o" || a == "+o")) ++i;
    if (py && (a == "-X" || a == "-W" || a == "-m")) { if (a == "-m") break; ++i; }
  }
  return {};
}

Hit strongProcessPattern(const std::vector<std::string>& argv, const std::string& exe) {
  Hit h;
  const std::string b = base(exe);
  std::string why;
  if (shellName(b)) {
    const std::string code = inlineCode(argv, exe);
    if (!code.empty() && shellCodeBad(code, why)) { h.matched = true; h.pattern = why; return h; }
  }
  if (pythonName(b) || scriptName(b)) {
    const std::string code = inlineCode(argv, exe);
    if (!code.empty() && scriptCodeBad(code, why)) { h.matched = true; h.pattern = why; return h; }
  }
  if (netTool(b)) {
    for (size_t i = 1; i < argv.size(); ++i)
      if (argv[i] == "-e" || argv[i] == "-c" || argv[i] == "--exec" || argv[i] == "--sh-exec" ||
          (shortCluster(argv[i], 'e') && argv[i].size() <= 4)) {
        h.matched = true;
        h.pattern = b + " -e";
        return h;
      }
  }
  if (b == "socat") {
    static const std::regex ex(R"(^(exec|system):)", std::regex::icase);
    for (size_t i = 1; i < argv.size(); ++i)
      if (std::regex_search(argv[i], ex)) { h.matched = true; h.pattern = "socat exec"; return h; }
  }
  return h;
}

}
}
