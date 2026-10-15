#include "ClamEngine.hpp"
#include <clamav.h>
#include <filesystem>
#include <iostream>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace oreon {
namespace fs = std::filesystem;

struct ClamEngine::Holder {
  cl_engine* eng{nullptr};
  ~Holder() {
    if (eng) cl_engine_free(eng);
  }
};

static std::once_flag gClInit;
static bool gClInitOk = false;

static void clamLogQuiet(enum cl_msg, const char*, const char*, void*) {}

ClamEngine::ClamEngine() {
  std::call_once(gClInit, [] {
    cl_set_clcb_msg(clamLogQuiet);
    gClInitOk = cl_init(CL_INIT_DEFAULT) == CL_SUCCESS;
  });
  status_.libVersion = cl_retver();
}

ClamEngine::~ClamEngine() { shutdown(); }

void ClamEngine::shutdown() {
  stopping_ = true;
  {
    std::lock_guard<std::mutex> l(loadMu_);
    if (loader_.joinable()) loader_.join();
  }
  std::lock_guard<std::mutex> lock(stMu_);
  if (dbstat_) {
    cl_statfree(dbstat_);
    delete dbstat_;
    dbstat_ = nullptr;
  }
}

bool ClamEngine::doLoad() {
  if (!gClInitOk) {
    std::lock_guard<std::mutex> lock(stMu_);
    status_.error = "libclamav failed to initialize";
    return false;
  }
  std::error_code ec;
  bool haveDb = false;
  if (fs::is_directory(dbDir_, ec)) {
    for (auto& e : fs::directory_iterator(dbDir_, ec)) {
      auto ext = e.path().extension().string();
      if (ext == ".cvd" || ext == ".cld" || ext == ".cud" || ext == ".hdb" ||
          ext == ".ndb" || ext == ".ldb" || ext == ".hsb" || ext == ".yara" || ext == ".yar") {
        haveDb = true;
        break;
      }
    }
  }
  if (!haveDb) {
    std::lock_guard<std::mutex> lock(stMu_);
    status_.available = engine_ != nullptr;
    status_.dbDir = dbDir_;
    status_.error = "No ClamAV signature database in " + dbDir_ +
                    ". Install clamav-update and run freshclam.";
    return false;
  }

  auto holder = std::make_shared<Holder>();
  holder->eng = cl_engine_new();
  if (!holder->eng) {
    std::lock_guard<std::mutex> lock(stMu_);
    status_.error = "cl_engine_new failed";
    return false;
  }
  cl_engine_set_num(holder->eng, CL_ENGINE_MAX_FILESIZE, static_cast<long long>(maxFileMb_) * 1024 * 1024);
  cl_engine_set_num(holder->eng, CL_ENGINE_MAX_SCANSIZE, static_cast<long long>(maxFileMb_) * 4 * 1024 * 1024);
  cl_engine_set_num(holder->eng, CL_ENGINE_MAX_SCANTIME, 30000);

  unsigned int sigs = 0;
  cl_error_t rc = cl_load(dbDir_.c_str(), holder->eng, &sigs, CL_DB_STDOPT);
  if (rc != CL_SUCCESS) {
    std::lock_guard<std::mutex> lock(stMu_);
    status_.error = std::string("cl_load: ") + cl_strerror(rc);
    return false;
  }
  rc = cl_engine_compile(holder->eng);
  if (rc != CL_SUCCESS) {
    std::lock_guard<std::mutex> lock(stMu_);
    status_.error = std::string("cl_engine_compile: ") + cl_strerror(rc);
    return false;
  }

  unsigned int daily = 0, mainv = 0;
  int64_t newest = 0;
  for (const char* base : {"daily", "main", "bytecode"}) {
    for (const char* ext : {".cld", ".cvd"}) {
      std::string p = dbDir_ + "/" + base + ext;
      if (!fs::exists(p, ec)) continue;
      cl_cvd* h = cl_cvdhead(p.c_str());
      if (!h) continue;
      if (std::strcmp(base, "daily") == 0) daily = h->version;
      if (std::strcmp(base, "main") == 0) mainv = h->version;
      if (static_cast<int64_t>(h->stime) > newest) newest = h->stime;
      cl_cvdfree(h);
      break;
    }
  }

  auto* st = new cl_stat;
  std::memset(st, 0, sizeof(*st));
  if (cl_statinidir(dbDir_.c_str(), st) != CL_SUCCESS) {
    delete st;
    st = nullptr;
  }

  {
    std::unique_lock<std::shared_mutex> lock(engMu_);
    engine_ = holder;
  }
  {
    std::lock_guard<std::mutex> lock(stMu_);
    if (dbstat_) {
      cl_statfree(dbstat_);
      delete dbstat_;
    }
    dbstat_ = st;
    status_.available = true;
    status_.dbDir = dbDir_;
    status_.signatures = sigs;
    status_.dailyVersion = daily;
    status_.mainVersion = mainv;
    status_.dbTime = newest;
    status_.loadedAt = static_cast<int64_t>(time(nullptr));
    status_.error.clear();
  }
  return true;
}

bool ClamEngine::loadNow() {
  loading_ = true;
  { std::lock_guard<std::mutex> lock(stMu_); status_.loading = true; }
  bool ok = doLoad();
  Status snap;
  {
    std::lock_guard<std::mutex> lock(stMu_);
    status_.loading = false;
    snap = status_;
  }
  loading_ = false;
  if (reloadCb_) reloadCb_(snap);
  return ok;
}

void ClamEngine::loadAsync() {
  std::lock_guard<std::mutex> l(loadMu_);
  if (loading_) return;
  if (loader_.joinable()) loader_.join();
  loading_ = true;
  { std::lock_guard<std::mutex> lock(stMu_); status_.loading = true; }
  loader_ = std::thread([this] {
    bool ok = doLoad();
    (void)ok;
    Status snap;
    {
      std::lock_guard<std::mutex> lock(stMu_);
      status_.loading = false;
      snap = status_;
    }
    loading_ = false;
    if (!stopping_ && reloadCb_) reloadCb_(snap);
  });
}

bool ClamEngine::checkForUpdates() {
  if (loading_) return false;
  bool changed = false;
  {
    std::lock_guard<std::mutex> lock(stMu_);
    if (dbstat_) {
      changed = cl_statchkdir(dbstat_) == 1;
    } else {
      std::error_code ec;
      if (!status_.available) {
        for (const char* f : {"/daily.cvd", "/daily.cld", "/main.cvd", "/main.cld"})
          if (fs::exists(dbDir_ + f, ec)) changed = true;
      }
    }
  }
  if (changed) loadAsync();
  return changed;
}

ClamEngine::Status ClamEngine::status() const {
  std::lock_guard<std::mutex> lock(stMu_);
  Status s = status_;
  s.loading = loading_;
  return s;
}

bool ClamEngine::ready() const {
  std::shared_lock<std::shared_mutex> lock(engMu_);
  return engine_ != nullptr;
}

ClamEngine::Result ClamEngine::scanFd(int fd, const std::string& displayName) const {
  Result r;
  std::shared_ptr<Holder> h;
  {
    std::shared_lock<std::shared_mutex> lock(engMu_);
    h = engine_;
  }
  if (!h || !h->eng) {
    r.error = true;
    r.message = "engine not loaded";
    return r;
  }
  cl_scan_options opts;
  std::memset(&opts, 0, sizeof(opts));
  opts.general = CL_SCAN_GENERAL_HEURISTICS;
  opts.parse = ~0u;
  opts.heuristic = 0;
  const char* vir = nullptr;
  unsigned long scanned = 0;
  cl_error_t rc = cl_scandesc(fd, displayName.c_str(), &vir, &scanned, h->eng, &opts);
  if (rc == CL_VIRUS) {
    r.infected = true;
    r.virusName = vir ? vir : "Unknown";
  } else if (rc != CL_CLEAN) {
    r.error = true;
    r.message = cl_strerror(rc);
  }
  return r;
}

ClamEngine::Result ClamEngine::scanFile(const std::string& path) const {
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) {
    Result r;
    r.error = true;
    r.message = std::strerror(errno);
    return r;
  }
  struct stat st{};
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    return {};
  }
  auto r = scanFd(fd, path);
  close(fd);
  return r;
}

}
