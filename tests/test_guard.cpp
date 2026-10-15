#include "Guard.hpp"
#include <iostream>
#include <cassert>

using namespace oreon::guard;

static int failures = 0;
static void check(bool c, const char* m) { if (!c) { std::cerr << "FAIL: " << m << "\n"; ++failures; } }

int main() {
  { ExecInputs in; in.inDevShm = true; check(execDecision(in) == ExecDecision::Block, "devshm block"); }
  { ExecInputs in; in.inTemp = true; check(execDecision(in) == ExecDecision::Alert, "tmp alert"); }
  { ExecInputs in; in.inDownloads = true; check(execDecision(in) == ExecDecision::Alert, "downloads alert"); }
  { ExecInputs in; in.inTemp = true; in.packageOwned = true; check(execDecision(in) == ExecDecision::Allow, "package allow"); }
  { ExecInputs in; in.inDevShm = true; in.trustedWriter = true; check(execDecision(in) == ExecDecision::Allow, "trusted allow"); }
  { ExecInputs in; in.inDevShm = true; in.allowListed = true; check(execDecision(in) == ExecDecision::Allow, "allowlist allow"); }

  check(looksLikeRansomName("/home/a/notes.docx.locked"), "ext locked");
  check(looksLikeRansomName("/home/a/HOW_TO_DECRYPT.txt"), "note name");
  check(!looksLikeRansomName("/home/a/photo.jpg"), "normal file");

  {
    RansomTracker rt;
    bool fired = false;
    for (int i = 0; i < 45; ++i) fired = rt.record("/home/a/f" + std::to_string(i), "modify", 1000) || fired;
    check(fired, "burst fires at count");
  }
  {
    RansomTracker rt;
    bool fired = false;
    for (int i = 0; i < 50; ++i) fired = rt.record("/home/a/f", "modify", int64_t(i) * 1000) || fired;
    check(!fired, "slow writes do not fire");
  }
  {
    RansomTracker rt;
    bool fired = rt.record("/a/x.locked", "rename", 10);
    fired = rt.record("/a/y.crypt", "rename", 20) || fired;
    fired = rt.record("/a/z.encrypted", "rename", 30) || fired;
    check(fired, "ransom names fire");
  }

  {
    auto d = persistenceDiff("line1\nline2\n", "line1\nline2\nevil\n");
    check(d.added == 1 && d.removed == 0, "diff added one");
    check(d.firstAdded == "evil", "diff first added");
    check(d.changed(), "diff changed");
  }
  {
    auto d = persistenceDiff("a\nb\n", "a\nb\n");
    check(!d.changed(), "no change");
  }

  if (failures) { std::cerr << failures << " failures\n"; return 1; }
  std::cout << "ok\n";
  return 0;
}
