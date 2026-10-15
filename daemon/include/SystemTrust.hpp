#pragma once
#include <string>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <cstdint>

namespace oreon {

namespace trust {

bool systemStagingPath(const std::string& path);

bool userWritableArea(const std::string& path);

bool droppableByUser(const std::string& path, const struct stat& st);

bool copyOfSystemFile(int fd, const std::string& path, const struct stat& st);


bool packageTransactionActive();

struct AutostartVerdict {
  bool suspicious{false};
  std::string reason;
};

bool isAutostartEntry(const std::string& path);

AutostartVerdict checkAutostart(const std::string& path, const std::string& content);

enum class SystemExe {
  No,
  RootPath,
  RpmVerified
};

SystemExe classifySystemExe(const std::string& path);

SystemExe classifyChrootExe(const std::string& root, const std::string& inner);

bool trustedChrootRoot(const std::string& root);

std::string processRoot(pid_t pid);

struct ExeView {
  bool ok{false};
  std::string root{"/"};
  std::string inner;
  std::string host;
  std::string comm;
  bool raced{false};
};
ExeView exeView(pid_t pid);

bool firstInWindow(const std::string& key, int64_t nowSec, int windowSec);

const char* systemExeName(SystemExe e);

enum class ActorTrust { Trusted, Untrusted, Unattributed };
const char* actorTrustName(ActorTrust t);

struct ActorVerdict {
  ActorTrust trust{ActorTrust::Unattributed};
  bool found{false};
  bool root{false};
  long uid{-1};
  int pid{0};
  int ppid{0};
  SystemExe exe{SystemExe::No};
  bool shellLike{false};
  std::string exePath;
  std::string chrootRoot;
  std::vector<std::string> reasons;
  std::string summary() const;
};

ActorVerdict assessActor(pid_t pid);

void noteProcess(pid_t pid);
void forgetProcessesForTests();

enum class ProcessAction { Ignore, AlertOnly, AlertAndKill };

ProcessAction decideProcess(const ActorVerdict& a, bool exeBad, bool wantKill);
const char* processActionName(ProcessAction a);

bool mayKill(const ActorVerdict& a);

bool protectedSystemProgram(const std::string& path);

using RpmDigestFn = std::string (*)(const std::string& root, const std::string& path);
void setRpmDigestFn(RpmDigestFn fn);

bool rpmFileDigestMatches(const std::string& root, const std::string& path);

void setExtraTrustedOwnerForTests(uid_t uid);

void setProcRoot(const std::string& root);

void setShownPathForTests(const std::string& real, const std::string& shown);

}
}
