/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "PerfCounters.h"

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <string>

#include "Flags.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"
#include "Task.h"

#include "LWP.h"

using namespace std;

namespace rr {

static bool attributes_initialized;
static struct perf_event_attr ticks_attr;
static struct perf_event_attr page_faults_attr;
static struct perf_event_attr hw_interrupts_attr;
static struct perf_event_attr instructions_retired_attr;

/*
 * Find out the cpu model using the cpuid instruction.
 * Full list of CPUIDs at http://sandpile.org/x86/cpuid.htm
 * Another list at
 * http://software.intel.com/en-us/articles/intel-architecture-and-processor-identification-with-cpuid-model-and-family-numbers
 */
enum CpuMicroarch {
  UnknownCpu,
  IntelMerom,
  IntelPenryn,
  IntelNehalem,
  IntelWestmere,
  IntelSandyBridge,
  IntelIvyBridge,
  IntelHaswell,
  IntelBroadwell,
  IntelSkylake,
  AMDFamily15h,
};

struct PmuConfig {
  CpuMicroarch uarch;
  const char* name;
  unsigned rcb_cntr_event;
  unsigned rinsn_cntr_event;
  unsigned hw_intr_cntr_event;
  bool supported;
  bool uses_lwp;
};

// XXX please only edit this if you really know what you're doing.
static const PmuConfig pmu_configs[] = {
  { IntelSkylake, "Intel Skylake", 0x5101c4, 0x5100c0, 0x5301cb, true, false },
  { IntelBroadwell, "Intel Broadwell", 0x5101c4, 0x5100c0, 0x5301cb, true, false },
  { IntelHaswell, "Intel Haswell", 0x5101c4, 0x5100c0, 0x5301cb, true, false },
  { IntelIvyBridge, "Intel Ivy Bridge", 0x5101c4, 0x5100c0, 0x5301cb, true, false },
  { IntelSandyBridge, "Intel Sandy Bridge", 0x5101c4, 0x5100c0, 0x5301cb,
    true, false },
  { IntelNehalem, "Intel Nehalem", 0x5101c4, 0x5100c0, 0x50011d, true, false },
  { IntelWestmere, "Intel Westmere", 0x5101c4, 0x5100c0, 0x50011d, true, false },
  { IntelPenryn, "Intel Penryn", 0, 0, 0, false, false },
  { IntelMerom, "Intel Merom", 0, 0, 0, false, false },
  { AMDFamily15h, "AMD family 15h", 0, 0, 0, true, true },
};

static string lowercase(const string& s) {
  string c = s;
  transform(c.begin(), c.end(), c.begin(), ::tolower);
  return c;
}

/**
 * Return the detected, known microarchitecture of this CPU, or don't
 * return; i.e. never return UnknownCpu.
 */
static CpuMicroarch get_cpu_microarch() {
  string forced_uarch = lowercase(Flags::get().forced_uarch);
  if (!forced_uarch.empty()) {
    for (size_t i = 0; i < array_length(pmu_configs); ++i) {
      const PmuConfig& pmu = pmu_configs[i];
      string name = lowercase(pmu.name);
      if (name.npos != name.find(forced_uarch)) {
        LOG(info) << "Using forced uarch " << pmu.name;
        return pmu.uarch;
      }
    }
    FATAL() << "Forced uarch " << Flags::get().forced_uarch << " isn't known.";
  }

  auto cpuid_data = cpuid(CPUID_GETFEATURES, 0);
  unsigned int cpu_type = (cpuid_data.eax & 0xF0FF0);
  switch (cpu_type) {
    case 0x006F0:
    case 0x10660:
      return IntelMerom;
    case 0x10670:
    case 0x106D0:
      return IntelPenryn;
    case 0x106A0:
    case 0x106E0:
    case 0x206E0:
      return IntelNehalem;
    case 0x20650:
    case 0x206C0:
    case 0x206F0:
      return IntelWestmere;
    case 0x206A0:
    case 0x206D0:
    case 0x306e0:
      return IntelSandyBridge;
    case 0x306A0:
      return IntelIvyBridge;
    case 0x306C0:
    case 0x306F0:
    case 0x40650:
    case 0x40660:
      return IntelHaswell;
    case 0x306D0:
    case 0x406F0:
    case 0x50660:
      return IntelBroadwell;
    case 0x406e0:
    case 0x506e0:
      return IntelSkylake;
    case 0x30f00:
      return AMDFamily15h;
    default:
      FATAL() << "CPU " << HEX(cpu_type) << " unknown.";
      return UnknownCpu; // not reached
  }
}

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

static void init_attributes() {
  if (attributes_initialized) {
    return;
  }
  attributes_initialized = true;

  CpuMicroarch uarch = get_cpu_microarch();
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

  if (pmu->uses_lwp) {
    FILE *f = fopen("/sys/devices/lwp/type", "r");
    if (!f)
      FATAL() << "LWP events not found";

    int type;
    if (fscanf(f, "%d", &type) != 1)
      FATAL() << "LWP events not found";

    fclose(f);

    init_perf_event_attr(&ticks_attr, (perf_type_id)type, 0);
  } else {
    init_perf_event_attr(&ticks_attr, PERF_TYPE_RAW, pmu->rcb_cntr_event);
  }
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
  init_attributes();
  return rr::ticks_attr;
}

PerfCounters::PerfCounters(Task* task, pid_t tid, bool add_offset) : task(task), tid(tid), started(false) {
  last_ticks_period = 0;
  saved_ticks = 0;
  ticks_read = add_offset ? LWP_OFFSET : 0;
  init_attributes();
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

void PerfCounters::reset(Ticks ticks_period) {
  assert(ticks_period >= 0);

  stop();

  ExtraRegisters& er = task->extra_regs();
  assert(!er.empty());

  if (ticks_period > 0xffffff)
    ticks_period = 0xffffff;

  saved_ticks = read_ticks_nondestructively();
  last_ticks_period = ticks_period;
  if (er.getLWPU32(0) || er.getLWPU32(1)) {
    er.setLWPU32(2, LWP_FLAGS);
    er.setLWPU32(3, 0);
    er.setLWPU32(7, LWP_FILTER);
    er.setLWPU32(16 + LWP_EVENT, ticks_period);
    task->extra_registers_changed = true;
  } else {
    last_ticks_period = 0;
    saved_ticks = 0;
  }
  //printf("ticks_read %ld -> %ld\n", ticks_read, saved_ticks);
  ticks_read = saved_ticks;

  struct perf_event_attr attr = rr::ticks_attr;
  attr.sample_period = 1;
  fd_ticks = start_counter(tid, -1, &attr);

  struct f_owner_ex own;
  own.type = F_OWNER_TID;
  own.pid = tid;
  if (fcntl(fd_ticks, F_SETOWN_EX, &own)) {
    FATAL() << "Failed to SETOWN_EX ticks event fd";
  }
  if (fcntl(fd_ticks, F_SETFL, O_ASYNC) ||
      fcntl(fd_ticks, F_SETSIG, PerfCounters::TIME_SLICE_SIGNAL)) {
    FATAL() << "Failed to make ticks counter ASYNC with sig"
            << signal_name(PerfCounters::TIME_SLICE_SIGNAL);
  }

  if (extra_perf_counters_enabled()) {
    int group_leader = fd_ticks;
    fd_hw_interrupts = start_counter(tid, group_leader, &hw_interrupts_attr);
    fd_instructions_retired =
        start_counter(tid, group_leader, &instructions_retired_attr);
    fd_page_faults = start_counter(tid, group_leader, &page_faults_attr);
  }

  //printf("TP %ld+%ld\n", (long)ticks_period, ticks_read);
  started = true;
}

void PerfCounters::stop() {
  if (!started) {
    return;
  }
  started = false;

  ExtraRegisters& er = task->extra_regs();
  if (er.empty())
    ASSERT(this->task, 0) << "ER empty";

  fd_ticks.close();
  fd_page_faults.close();
  fd_hw_interrupts.close();
  fd_instructions_retired.close();

  saved_ticks = read_ticks_nondestructively();
  //printf("stop at %ld\n", saved_ticks);
  last_ticks_period = 0;
  er.setLWPU32(2, 0);
  er.setLWPU32(3, 0);
  er.setLWPU32(7, 0);
  er.setLWPU32(16 + LWP_EVENT, 0);
  task->extra_registers_changed = true;
  //printf("stopped at %ld ticks\n", saved_ticks);
}

Ticks PerfCounters::read_ticks() {
  long ticks = read_ticks_nondestructively();
  long ret = ticks - ticks_read;
  ticks_read = ticks;
  //printf("ticks %ld\n", ticks_read);
  return ret;
}

Ticks PerfCounters::read_ticks_nondestructively() {
  ExtraRegisters& er = task->extra_regs();
  if (er.empty())
    ASSERT(this->task, 0) << "ER empty";
  if (er.empty())
    abort();
  if (er.getLWPU32(0) || er.getLWPU32(1)) {
    if (er.getLWPU32(3) > 0x20) {
      ASSERT(this->task, er.getLWPU32(3) <= 0x20) << "missed an interrupt";
    }
    if (er.getLWPU32(3) == 0x20 || (er.getLWPU32(8)&0xff)) {
      if (er.getLWPU32(16+LWP_EVENT) & 0x1000000)
        ;
      else
        ASSERT(this->task, 0) << "extra interrupt, counter " << er.getLWPU32(16+LWP_EVENT);
    } else {
      if (er.getLWPU32(16+LWP_EVENT) & 0x1000000)
        ASSERT(this->task, 0) << "missed interrupt";
    }
    long counter_value = er.getLWPU32(16+LWP_EVENT);
#if 0
    long diff = (last_ticks_period - counter_value) & 0xffff;
#else
    //printf("[pre] cv %ld ltp %ld\n", counter_value, last_ticks_period);
    counter_value |= (counter_value & 0x1000000) ? 0xffffffffff000000 : 0;
    //printf("cv %ld ltp %ld\n", counter_value, last_ticks_period);
    assert(counter_value >= -2048);
    long diff = (last_ticks_period - counter_value);// & 0xffffff;
    assert(diff >= 0);
#endif
    long ret = saved_ticks;
    ret += diff;
    return ret;
  } else {
    return saved_ticks;
  }
}

static int64_t read_counter(ScopedFd& fd) {
  int64_t val;
  ssize_t nread = read(fd, &val, sizeof(val));
  assert(nread == sizeof(val));
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
