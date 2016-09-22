/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "log.h"

#include <stdlib.h>

#include <memory>
#include <sstream>
#include <unordered_map>

#include "Flags.h"
#include "GdbServer.h"
#include "RecordSession.h"
#include "ftrace.h"
#include "kernel_metadata.h"
#include "util.h"

using namespace std;

namespace rr {

struct LogModule {
  string name;
  LogLevel level;
};

static LogLevel to_log_level(const string& str) {
  if (str == "debug") {
    return LOG_debug;
  }
  if (str == "info") {
    return LOG_info;
  }
  if (str == "warn") {
    return LOG_warn;
  }
  if (str == "error") {
    return LOG_error;
  }
  if (str == "fatal") {
    return LOG_fatal;
  }
  fprintf(stderr, "Log level %s in RR_LOG is not valid, assuing 'fatal'\n",
          str.c_str());
  return LOG_fatal;
}

static char simple_to_lower(char ch) {
  // to_lower sucks because it's locale-dependent
  if (ch >= 'A' && ch <= 'Z') {
    return ch + 'a' - 'A';
  }
  return ch;
}

static string simple_to_lower(const string& s) {
  char* buf = new char[s.size() + 1];
  for (size_t i = 0; i < s.size(); ++i) {
    buf[i] = simple_to_lower(s[i]);
  }
  buf[s.size()] = 0;
  return string(buf);
}

#if __has_attribute(require_constant_initialization)
#define _CONSTANT_STATIC                                                       \
  __attribute__((__require_constant_initialization__)) static
#else
#define _CONSTANT_STATIC static
#endif

static bool log_globals_initialized = false;
static LogLevel default_level = LOG_error;

// These need to be available to other static constructors, so we need to be
// sure that they const constant-initialized. Unfortunately some versions of C++
// libraries have a bug that causes them not to be. _CONSTANT_STATIC should
// turn this into a compile error rather than a runtime crash for compilers
// that support the attribute.
_CONSTANT_STATIC unique_ptr<unordered_map<string, LogLevel>> level_map;
_CONSTANT_STATIC unique_ptr<unordered_map<const char*, LogModule>> log_modules;
_CONSTANT_STATIC std::unique_ptr<stringstream> logging_stream;

static void init_log_globals() {
  if (log_globals_initialized) {
    return;
  }
  log_globals_initialized = true;
  level_map = unique_ptr<unordered_map<string, LogLevel>>(
      new unordered_map<string, LogLevel>());
  log_modules = unique_ptr<unordered_map<const char*, LogModule>>(
      new unordered_map<const char*, LogModule>());
  logging_stream = unique_ptr<stringstream>(new stringstream());

  const char* log_env = "RR_LOG";
  if (running_under_rr()) {
    log_env = "RR_UNDER_RR_LOG";
  }
  char* env = getenv(log_env);
  if (env) {
    env = strdup(env);
    for (int i = 0; env[i]; ++i) {
      env[i] = simple_to_lower(env[i]);
    }
    char* p = env;
    while (*p) {
      char* end = strchrnul(p, ',');
      char* sep = strchrnul(p, ':');
      string n;
      LogLevel level;
      if (sep >= end) {
        n = string(p, end - p);
        level = LOG_debug;
      } else {
        n = string(p, sep - p);
        if (sep + 1 == end) {
          level = LOG_fatal;
        } else {
          level = to_log_level(string(sep + 1, end - (sep + 1)));
        }
      }
      if (n == "" || n == "all") {
        level_map->clear();
        default_level = level;
      } else {
        (*level_map)[n] = level;
      }
      if (*end) {
        p = end + 1;
      } else {
        p = end;
      }
    }
    free(env);
  }
}

static LogLevel get_log_level(const string& name) {
  init_log_globals();

  auto it = level_map->find(simple_to_lower(name));
  if (it == level_map->end()) {
    return default_level;
  }
  return it->second;
}

static string file_to_name(const char* file) {
  const char* base = strrchr(file, '/');
  if (base) {
    ++base;
  } else {
    base = file;
  }
  const char* dot = strrchr(base, '.');
  string r;
  if (dot) {
    r = string(base, dot - base);
  } else {
    r = string(base);
  }
  return r;
}

static LogModule& get_log_module(const char* file) {
  init_log_globals();

  auto it = log_modules->find(file);
  if (it != log_modules->end()) {
    return it->second;
  }
  LogModule m;
  m.name = file_to_name(file);
  m.level = get_log_level(m.name);
  (*log_modules)[file] = m;
  return (*log_modules)[file];
}

void set_all_logging(LogLevel level) {
  default_level = level;
  level_map->clear();
  log_modules->clear();
}

void set_logging(const char* name, LogLevel level) {
  (*level_map)[simple_to_lower(name)] = level;
  log_modules->clear();
}

static const char* log_name(LogLevel level) {
  switch (level) {
    case LOG_fatal:
      return "FATAL";
    case LOG_error:
      return "ERROR";
    case LOG_warn:
      return "WARN";
    case LOG_info:
      return "INFO";
    default:
      return "???";
  }
}

ostream& log_stream() {
  init_log_globals();
  return *logging_stream;
}

static void flush_log_stream() {
  cerr << logging_stream->str();
  ftrace::write(logging_stream->str());
  logging_stream->str(string());
}

template <typename T>
static void write_prefix(T& stream, LogLevel level, const char* file, int line,
                         const char* function) {
  int err = errno;
  stream << "[" << log_name(level) << " ";
  if (level <= LOG_error) {
    stream << file << ":" << line << ":";
  }
  stream << function << "()";
  if (level <= LOG_warn) {
    stream << " errno: " << errno_name(err);
  }
  stream << "] ";
}

NewlineTerminatingOstream::NewlineTerminatingOstream(LogLevel level,
                                                     const char* file, int line,
                                                     const char* function)
    : level(level) {
  LogModule& m = get_log_module(file);
  enabled = level <= m.level;
  if (enabled) {
    if (level == LOG_debug) {
      *this << "[" << m.name << "] ";
    } else {
      write_prefix(*this, level, file, line, function);
    }
  }
}

NewlineTerminatingOstream::~NewlineTerminatingOstream() {
  if (enabled) {
    log_stream() << std::endl;
    flush_log_stream();
    if (Flags::get().fatal_errors_and_warnings && level <= LOG_warn) {
      //abort();
    }
  }
}

FatalOstream::FatalOstream(const char* file, int line, const char* function) {
  write_prefix(*this, LOG_fatal, file, line, function);
}

FatalOstream::~FatalOstream() {
  log_stream() << std::endl;
  flush_log_stream();
  abort();
}

static void emergency_debug(Task* t) {
  ftrace::stop();

  // Enable SIGINT in case it was disabled. Users want to be able to ctrl-C
  // out of this.
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_DFL;
  sigaction(SIGINT, &sa, nullptr);

  RecordSession* record_session = t->session().as_record();
  if (record_session) {
    record_session->trace_writer().close();
  }

  if (probably_not_interactive() && !Flags::get().force_things) {
    errno = 0;
    FATAL()
        << "(session doesn't look interactive, aborting emergency debugging)";
  }

  GdbServer::emergency_debug(t);
  FATAL() << "Can't resume execution from invalid state";
}

EmergencyDebugOstream::EmergencyDebugOstream(bool cond, const Task* t,
                                             const char* file, int line,
                                             const char* function,
                                             const char* cond_str)
    : t(const_cast<Task*>(t)), cond(cond) {
  if (!cond) {
    write_prefix(*this, LOG_fatal, file, line, function);
    *this << "\n (task " << t->tid << " (rec:" << t->rec_tid << ") at time "
          << t->trace_time() << ")"
          << "\n -> Assertion `" << cond_str << "' failed to hold. ";
  }
}

EmergencyDebugOstream::~EmergencyDebugOstream() {
  if (!cond) {
    log_stream() << std::endl;
    flush_log_stream();
    t->log_pending_events();
    emergency_debug(t);
  }
}

ostream& operator<<(ostream& stream, const vector<uint8_t>& bytes) {
  for (uint32_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) {
      stream << ' ';
    }
    stream << HEX(bytes[i]);
  }
  return stream;
}

} // namespace rr
