#include "ChangeAssess.hpp"
#include <oreon/Hash.hpp>
#include <algorithm>
#include <map>
#include <set>
#include <sstream>

namespace oreon {
namespace change {

namespace {

bool endsWith(const std::string& s, const std::string& e) {
  return s.size() >= e.size() && s.compare(s.size() - e.size(), e.size(), e) == 0;
}

std::vector<std::string> lines(const std::string& t) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : t) {
    if (c == '\n') { out.push_back(cur); cur.clear(); }
    else if (c != '\r') cur += c;
  }
  if (!cur.empty()) out.push_back(cur);
  return out;
}

std::vector<std::string> fields(const std::string& l, char sep) {
  std::vector<std::string> f;
  std::string cur;
  for (char c : l) {
    if (c == sep) { f.push_back(cur); cur.clear(); }
    else cur += c;
  }
  f.push_back(cur);
  return f;
}

std::string trim(const std::string& s) {
  size_t a = s.find_first_not_of(" \t"), b = s.find_last_not_of(" \t");
  return a == std::string::npos ? std::string() : s.substr(a, b - a + 1);
}

bool numeric(const std::string& s) {
  return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isdigit(c); });
}

struct ColonFile {
  std::map<std::string, std::vector<std::string>> rows;
  bool malformed{false};
  std::string why;
};

ColonFile parseColon(const std::string& text, size_t want, int numericField) {
  ColonFile cf;
  int n = 0;
  for (const auto& l : lines(text)) {
    ++n;
    if (l.empty() || l[0] == '#') continue;
    auto f = fields(l, ':');
    if (f.size() != want || f[0].empty() ||
        (numericField >= 0 && !numeric(f[static_cast<size_t>(numericField)]))) {
      cf.malformed = true;
      if (cf.why.empty()) cf.why = "line " + std::to_string(n) + " does not have the expected layout";
      continue;
    }
    cf.rows[f[0]] = f;
  }
  return cf;
}

struct SudoRule { std::string who; bool all{false}; bool nopasswd{false}; };

std::vector<SudoRule> sudoRules(const std::string& text) {
  std::vector<SudoRule> out;
  for (auto l : lines(text)) {
    l = trim(l);
    if (l.empty() || l[0] == '#' || l.rfind("Defaults", 0) == 0 || l.rfind("@include", 0) == 0 ||
        l.rfind("#include", 0) == 0)
      continue;
    if (l.find('=') == std::string::npos) continue;
    std::string who = l.substr(0, l.find_first_of(" \t"));
    if (who.rfind("User_Alias", 0) == 0 || who.rfind("Cmnd_Alias", 0) == 0 ||
        who.rfind("Host_Alias", 0) == 0 || who.rfind("Runas_Alias", 0) == 0)
      continue;
    SudoRule r;
    r.who = who;
    std::string rhs = l.substr(l.find('=') + 1);
    r.nopasswd = rhs.find("NOPASSWD") != std::string::npos;
    std::string tail = trim(rhs.substr(rhs.find_last_of(":)") == std::string::npos ? 0 : rhs.find_last_of(":)") + 1));
    r.all = tail == "ALL";
    out.push_back(r);
  }
  return out;
}

}

FileKind kindOf(const std::string& path) {
  if (endsWith(path, "/etc/passwd")) return FileKind::Passwd;
  if (endsWith(path, "/etc/shadow")) return FileKind::Shadow;
  if (endsWith(path, "/etc/group")) return FileKind::Group;
  if (endsWith(path, "/etc/gshadow")) return FileKind::GShadow;
  if (endsWith(path, "/etc/sudoers") || path.find("/etc/sudoers.d/") != std::string::npos)
    return FileKind::Sudoers;
  if (endsWith(path, "/.ssh/authorized_keys") || endsWith(path, "/.ssh/authorized_keys2"))
    return FileKind::AuthorizedKeys;
  if (endsWith(path, "/etc/ld.so.preload")) return FileKind::Preload;
  if (endsWith(path, "/.oreon-defense-keepsafe")) return FileKind::Canary;
  return FileKind::Persistence;
}

Delta analyze(const std::string& path, const std::string& before, const std::string& after) {
  Delta d;
  switch (kindOf(path)) {
  case FileKind::Passwd: {
    auto a = parseColon(before, 7, 2), b = parseColon(after, 7, 2);
    if (b.malformed && !a.malformed) { d.malformed = true; d.malformedWhy = b.why; }
    for (const auto& [name, f] : b.rows) {
      auto old = a.rows.find(name);
      const bool isNew = old == a.rows.end();
      if (f[2] == "0" && name != "root" && (isNew || old->second[2] != "0")) {
        d.critical.push_back("A second administrator account with user ID 0 was added: " + name);
        d.criticalIsTop = true;
      }
      if (name == "root" && f[1].empty() && (isNew || !old->second[1].empty())) {
        d.critical.push_back("The root account no longer needs a password");
        d.criticalIsTop = true;
      }
      if (isNew) d.notes.push_back("new account " + name + " (uid " + f[2] + ")");
    }
    for (const auto& [name, f] : a.rows)
      if (!b.rows.count(name)) d.notes.push_back("removed account " + name);
    break;
  }
  case FileKind::Shadow: {
    auto a = parseColon(before, 9, -1), b = parseColon(after, 9, -1);
    if (b.malformed && !a.malformed) { d.malformed = true; d.malformedWhy = b.why; }
    auto r = b.rows.find("root");
    if (r != b.rows.end() && r->second[1].empty()) {
      auto o = a.rows.find("root");
      if (o == a.rows.end() || !o->second[1].empty()) {
        d.critical.push_back("The root account no longer needs a password");
        d.criticalIsTop = true;
      }
    }
    for (const auto& [name, f] : b.rows)
      if (!a.rows.count(name)) d.notes.push_back("password entry for " + name);
    break;
  }
  case FileKind::Group:
  case FileKind::GShadow: {
    const bool g = kindOf(path) == FileKind::Group;
    auto a = parseColon(before, 4, g ? 2 : -1), b = parseColon(after, 4, g ? 2 : -1);
    if (b.malformed && !a.malformed) { d.malformed = true; d.malformedWhy = b.why; }
    if (g) {
      for (const auto& [name, f] : b.rows) {
        if (f[2] != "0") continue;
        std::set<std::string> was;
        auto o = a.rows.find(name);
        if (o != a.rows.end()) for (auto& m : fields(o->second[3], ',')) was.insert(m);
        for (auto& m : fields(f[3], ','))
          if (!m.empty() && !was.count(m))
            d.critical.push_back("User " + m + " was added to the root group");
      }
    }
    for (const auto& [name, f] : b.rows)
      if (!a.rows.count(name)) d.notes.push_back("new group " + name);
    break;
  }
  case FileKind::Sudoers: {
    std::set<std::string> admins = {"root"};
    for (const auto& r : sudoRules(before)) if (r.all) admins.insert(r.who);
    auto oldRules = sudoRules(before);
    for (const auto& r : sudoRules(after)) {
      bool existed = std::any_of(oldRules.begin(), oldRules.end(), [&](const SudoRule& o) {
        return o.who == r.who && o.all == r.all && o.nopasswd == r.nopasswd;
      });
      if (existed) continue;
      if (r.all && r.nopasswd && !admins.count(r.who))
        d.critical.push_back("Admin rights without a password were given to " + r.who);
      else if (r.all && !admins.count(r.who))
        d.grants.push_back(r.who);
      else
        d.notes.push_back("rule changed for " + r.who);
    }
    break;
  }
  case FileKind::AuthorizedKeys: {
    const bool rootKeys = path.rfind("/root/", 0) == 0 || path.find("/root/.ssh/") != std::string::npos;
    std::set<std::string> was;
    for (auto& l : lines(before)) { l = trim(l); if (!l.empty() && l[0] != '#') was.insert(l); }
    for (auto l : lines(after)) {
      l = trim(l);
      if (l.empty() || l[0] == '#' || was.count(l)) continue;
      if (rootKeys) {
        d.critical.push_back("A new key can now log in as root over SSH");
        d.criticalIsTop = true;
      } else {
        d.notes.push_back("new SSH key");
      }
    }
    break;
  }
  case FileKind::Preload: {
    for (auto l : lines(after)) {
      l = trim(l);
      if (l.empty() || l[0] == '#') continue;
      if (before.find(l) == std::string::npos)
        d.critical.push_back("A library is now loaded into every program: " + l);
    }
    break;
  }
  default:
    break;
  }
  return d;
}

bool matchesRpm(const std::string& path) {
  return trust::rpmFileDigestMatches("/", path);
}

Verdict assess(const Event& e) {
  Verdict v;
  const FileKind kind = kindOf(e.path);
  const bool account = kind == FileKind::Passwd || kind == FileKind::Shadow || kind == FileKind::Group ||
                       kind == FileKind::GShadow;
  const bool priv = account || kind == FileKind::Sudoers || kind == FileKind::Preload ||
                    (kind == FileKind::AuthorizedKeys && e.path.find("/root/") != std::string::npos);
  v.category = kind == FileKind::Canary ? "ransomware" : priv ? "privesc" : "persistence";
  const Delta d = analyze(e.path, e.before, e.after);
  std::string notes;
  for (const auto& n : d.notes) notes += (notes.empty() ? "" : ", ") + n;
  for (const auto& n : d.grants) notes += (notes.empty() ? "" : ", ") + ("admin rights given to " + n);
  v.detail = notes;

  if (e.attributed) v.reasons.push_back("writer: " + e.actor.summary());
  else v.reasons.push_back("writer unknown");

  if (!d.critical.empty()) {
    v.alert = true;
    v.severity = d.criticalIsTop ? Severity::Critical : Severity::High;
    v.title = "Admin access was changed in a risky way";
    v.message = d.critical.front() + ".";
    for (size_t i = 1; i < d.critical.size(); ++i) v.detail = d.critical[i] + (v.detail.empty() ? "" : "; " + v.detail);
    v.reasons.push_back("risky content change");
    v.killWriter = e.attributed && e.actor.trust != trust::ActorTrust::Trusted;
    return v;
  }
  if (d.malformed) {
    v.alert = true;
    v.severity = Severity::Medium;
    v.title = "A system account file looks damaged";
    v.message = "The file no longer has the expected layout: " + d.malformedWhy + ".";
    v.reasons.push_back("structure check failed");
    return v;
  }

  if (e.attributed && e.actor.trust == trust::ActorTrust::Trusted) {
    v.reasons.push_back("trusted writer and ancestry");
    return v;
  }
  if (e.attributed && e.actor.trust == trust::ActorTrust::Untrusted) {
    v.alert = true;
    v.reasons.push_back("untrusted writer or ancestry");
    if (kind == FileKind::Canary) {
      v.severity = Severity::Critical;
      v.title = "A program tried to change your protected files";
      v.message = "Something changed a protected file. This can be a sign of ransomware.";
      v.killWriter = true;
    } else if (priv) {
      v.severity = Severity::High;
      v.title = "A sensitive system file changed";
      v.message = "A program that is not part of the system changed a file that controls accounts or admin rights.";
    } else {
      v.severity = Severity::Medium;
      v.title = "A startup file changed";
      v.message = "A program that is not part of the system changed a file that can start programs automatically.";
    }
    return v;
  }

  if (e.packageCopy) {
    v.reasons.push_back("content matches the package database");
    return v;
  }
  if (kind == FileKind::Canary) {
    v.alert = true;
    v.severity = Severity::High;
    v.title = "A program tried to change your protected files";
    v.message = "Something changed a protected file. This can be a sign of ransomware.";
    return v;
  }
  if (account) {
    v.reasons.push_back("account file layout and changes look normal");
    return v;
  }
  if (kind == FileKind::Sudoers) {
    if (!d.grants.empty()) {
      v.alert = true;
      v.severity = Severity::Medium;
      v.title = "Admin rights were given to someone new";
      v.message = "A sudo rule now gives full admin rights to " + d.grants.front() + ".";
      return v;
    }
    v.reasons.push_back("sudo rules changed without new admin rights");
    return v;
  }
  if (kind == FileKind::AuthorizedKeys) {
    v.reasons.push_back("user SSH keys changed, writer unknown");
    if (d.notes.empty()) return v;
    v.alert = true;
    v.severity = Severity::Medium;
    v.title = "A new SSH key was added";
    v.message = "A new key can log in to this account over SSH.";
    return v;
  }
  v.alert = true;
  v.severity = Severity::Medium;
  v.title = "A startup file changed";
  v.message = "A file that can start programs automatically was changed.";
  return v;
}

}
}
