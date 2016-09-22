/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "PerfCounters.h"

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <string>

#include "TicksSource.h"
#include "Flags.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

static bool attributes_initialized;
static struct perf_event_attr ticks_attr;
static struct perf_event_attr cycles_attr;
static struct perf_event_attr page_faults_attr;
static struct perf_event_attr hw_interrupts_attr;
static struct perf_event_attr instructions_retired_attr;

struct PmuConfig {
  CpuMicroarch uarch;
  const char* name;
  unsigned rcb_cntr_event;
  unsigned rinsn_cntr_event;
  unsigned hw_intr_cntr_event;
  bool supported;
};

// XXX please only edit this if you really know what you're doing.
static const PmuConfig pmu_configs[] = {
  { IntelSkylake, "Intel Skylake", 0x5101c4, 0x5100c0, 0x5301cb, true },
  { IntelBroadwell, "Intel Broadwell", 0x5101c4, 0x5100c0, 0x5301cb, true },
  { IntelHaswell, "Intel Haswell", 0x5101c4, 0x5100c0, 0x5301cb, true },
  { IntelIvyBridge, "Intel Ivy Bridge", 0x5101c4, 0x5100c0, 0x5301cb, true },
  { IntelSandyBridge, "Intel Sandy Bridge", 0x5101c4, 0x5100c0, 0x5301cb,
    true },
  { IntelNehalem, "Intel Nehalem", 0x5101c4, 0x5100c0, 0x50011d, true },
  { IntelWestmere, "Intel Westmere", 0x5101c4, 0x5100c0, 0x50011d, true },
  { IntelPenryn, "Intel Penryn", 0, 0, 0, false },
  { IntelMerom, "Intel Merom", 0, 0, 0, false },
};

static void init_perf_event_attr(struct perf_event_attr* attr,
                                 perf_type_id type, unsigned config) {
  memset(attr, 0, sizeof(*attr));
  attr->type = type;
  attr->size = sizeof(*attr);
  attr->config = config;
  // rr requires that its events count userspace tracee code
  // only.
  attr->exclude_kernel = 1;
  attr->exclude_guest = 1;
}

static void init_attributes(CpuMicroarch uarch) {
  if (attributes_initialized) {
    return;
  }
  attributes_initialized = true;

  const PmuConfig* pmu = nullptr;
  for (size_t i = 0; i < array_length(pmu_configs); ++i) {
    if (uarch == pmu_configs[i].uarch) {
      pmu = &pmu_configs[i];
      break;
    }
  }
  assert(pmu);

  if (!pmu->supported) {
    FATAL() << "Microarchitecture `" << pmu->name << "' currently unsupported.";
  }

  init_perf_event_attr(&ticks_attr, PERF_TYPE_RAW, pmu->rcb_cntr_event);
  init_perf_event_attr(&cycles_attr, PERF_TYPE_HARDWARE,
                       PERF_COUNT_HW_CPU_CYCLES);
  init_perf_event_attr(&instructions_retired_attr, PERF_TYPE_RAW,
                       pmu->rinsn_cntr_event);
  init_perf_event_attr(&hw_interrupts_attr, PERF_TYPE_RAW,
                       pmu->hw_intr_cntr_event);
  // libpfm encodes the event with this bit set, so we'll do the
  // same thing.  Unclear if necessary.
  hw_interrupts_attr.exclude_hv = 1;
  init_perf_event_attr(&page_faults_attr, PERF_TYPE_SOFTWARE,
                       PERF_COUNT_SW_PAGE_FAULTS);
}

const struct perf_event_attr& PerfCounters::ticks_attr() {
  return rr::ticks_attr;
}

PerfCounters::PerfCounters(CpuMicroarch uarch, pid_t tid)
  : tid(tid), started(false) {
  init_attributes(uarch);
}

static ScopedFd start_counter(pid_t tid, int group_fd,
                              struct perf_event_attr* attr) {
  int fd = syscall(__NR_perf_event_open, attr, tid, -1, group_fd, 0);
  if (0 > fd) {
    if (errno == EACCES) {
      FATAL() << "Permission denied to use 'perf_event_open'; are perf events "
                 "enabled? Try 'perf record'.";
    }
    if (errno == ENOENT) {
      FATAL() << "Unable to open performance counter with 'perf_event_open'; "
                 "are perf events enabled? Try 'perf record'.";
    }
    FATAL() << "Failed to initialize counter";
  }
  if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)) {
    FATAL() << "Failed to start counter";
  }
  return fd;
}

static bool has_ioc_period_bug() {
  static bool did_test = false;
  static bool bug_detected = true;
  if (did_test) {
    return bug_detected;
  }

  // Start a cycles counter
  struct perf_event_attr attr = rr::cycles_attr;
  attr.sample_period = 0xfffffff;
  attr.exclude_kernel = 0;
  attr.disabled = 0;
  ScopedFd bug_fd = start_counter(0, -1, &attr);

  uint64_t new_period = 1;
  if (ioctl(bug_fd, PERF_EVENT_IOC_PERIOD, &new_period)) {
    FATAL() << "ioctl(PERF_EVENT_IOC_PERIOD) failed";
  }

  struct pollfd poll_bug_fd = {.fd = bug_fd, .events = POLL_IN, .revents = 0 };
  poll(&poll_bug_fd, 1, 0);

  bug_detected = poll_bug_fd.revents == 0;

  did_test = true;
  return bug_detected;
}

static void make_counter_async(ScopedFd& fd, int signal) {
  if (fcntl(fd, F_SETFL, O_ASYNC) || fcntl(fd, F_SETSIG, signal)) {
    FATAL() << "Failed to make ticks counter ASYNC with sig"
            << signal_name(signal);
  }
}

void PerfCounters::reset(Ticks ticks_period) {
  assert(ticks_period >= 0);

  if (!started) {
    struct perf_event_attr attr = rr::ticks_attr;
    attr.sample_period = ticks_period;
    fd_ticks = start_counter(tid, -1, &attr);

    struct f_owner_ex own;
    own.type = F_OWNER_TID;
    own.pid = tid;
    if (fcntl(fd_ticks, F_SETOWN_EX, &own)) {
      FATAL() << "Failed to SETOWN_EX ticks event fd";
    }
    make_counter_async(fd_ticks, PerfCounters::TIME_SLICE_SIGNAL);

    if (extra_perf_counters_enabled()) {
      int group_leader = fd_ticks;
      fd_hw_interrupts = start_counter(tid, group_leader, &hw_interrupts_attr);
      fd_instructions_retired =
          start_counter(tid, group_leader, &instructions_retired_attr);
      fd_page_faults = start_counter(tid, group_leader, &page_faults_attr);
    }
  } else {
    if (ioctl(fd_ticks, PERF_EVENT_IOC_RESET, 0)) {
      FATAL() << "ioctl(PERF_EVENT_IOC_RESET) failed";
    }
    if (ioctl(fd_ticks, PERF_EVENT_IOC_PERIOD, &ticks_period)) {
      FATAL() << "ioctl(PERF_EVENT_IOC_PERIOD) failed";
    }
    if (ioctl(fd_ticks, PERF_EVENT_IOC_ENABLE, 0)) {
      FATAL() << "ioctl(PERF_EVENT_IOC_ENABLE) failed";
    }
  }

  started = true;
  counting = true;
}

void PerfCounters::set_tid(pid_t tid) {
  stop();
  this->tid = tid;
}

void PerfCounters::stop() {
  if (!started) {
    return;
  }
  started = false;

  fd_ticks.close();
  fd_page_faults.close();
  fd_hw_interrupts.close();
  fd_instructions_retired.close();
}

void PerfCounters::stop_counting() {
  counting = false;
  if (has_ioc_period_bug()) {
    stop();
  } else {
    ioctl(fd_ticks, PERF_EVENT_IOC_DISABLE, 0);
  }
}

bool PerfCounters::start_with_interval(Ticks ticks) {
  reset(ticks);

  return false;
}

Ticks PerfCounters::stop_and_read() {
  Ticks ret = read_ticks();

  stop();

  return ret;
}

static int64_t read_counter(ScopedFd& fd) {
  int64_t val;
  ssize_t nread = read(fd, &val, sizeof(val));
  assert(nread == sizeof(val));
  return val;
}

Ticks PerfCounters::read_ticks() {
  uint64_t val = started && counting ? read_counter(fd_ticks) : 0;
  return val;
}

PerfCounters::Extra PerfCounters::read_extra() {
  assert(extra_perf_counters_enabled());

  Extra extra;
  if (started) {
    extra.page_faults = read_counter(fd_page_faults);
    extra.hw_interrupts = read_counter(fd_hw_interrupts);
    extra.instructions_retired = read_counter(fd_instructions_retired);
  } else {
    memset(&extra, 0, sizeof(extra));
  }
  return extra;
}

} // namespace rr
