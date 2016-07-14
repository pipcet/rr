extern "C" {
#include <sys/ptrace.h>
#include <asm/ptrace.h>
}
#include <elf.h>
#include "LWP.h"
#include "PerfCounters.h"

#include <asm/ldt.h>
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

#include "AddressSpace.h"
#include "Event.h"
#include "ExtraRegisters.h"
#include "FdTable.h"
#include "PerfCounters.h"
#include "LWP.h"
#include "PropertyTable.h"
#include "Registers.h"
#include "TaskishUid.h"
#include "TraceStream.h"
#include "WaitStatus.h"
#include "kernel_abi.h"
#include "kernel_supplement.h"
#include "remote_code_ptr.h"
#include "util.h"

using namespace std;

namespace rr {
void LWP::init_buffer(remote_ptr<void> buffer, size_t buffer_size)
{
  assert(buffer);
  assert(buffer_size >= 32 * 32);
  assert(buffer_size % 32 == 0);

  memset(&lwpcb, 0, sizeof lwpcb);
  lwpcb.flags = LWP_FLAGS;
  lwpcb.buffer_size = buffer_size;
  lwpcb.buffer_base = buffer.as_int();
  lwpcb.filters = LWP_FILTERS;
  lwpcb.event[LWP_EVENT].interval = LWP_INTERVAL;

  memset(&xsave, 0, sizeof xsave);
  xsave.flags = LWP_FLAGS;
  xsave.buffer_size = buffer_size;
  xsave.buffer_base = buffer.as_int();
  xsave.filters = LWP_FILTERS;
}

bool LWP::write_lwpcb(remote_ptr<struct lwpcb> dest_lwp)
{
  remote_ptr<long> dest = remote_ptr<long>(dest_lwp.as_int());
  long *src = (long *)&lwpcb;
  assert(task);
  assert(dest);

  unsigned int i;
  for (i = 0; i < (sizeof(lwpcb) + 7) / 8; i++) {
    if (!task->ptrace_if_alive(PTRACE_POKEDATA, dest + i, &src[i]))
      return false;
  }

  return true;
}

unsigned LWP::xsave_area_size = 0;
unsigned LWP::xsave_lwp_size = 0;
unsigned LWP::xsave_lwp_off = 0;

bool LWP::read_lwp_xsave()
{
  char *buf = (char *)malloc(xsave_area_size);
  if (!buf)
    return false;
  struct iovec vec = { buf, xsave_area_size };
  if (!task->ptrace_if_alive(PTRACE_GETREGSET, NT_X86_XSTATE, &vec))
    return false;
  if (vec.iov_len != xsave_area_size)
    return false;
  memcpy(&xsave, buf, sizeof xsave);
  free(buf);

  return true;
}

bool LWP::lwp_xsave_to_lwpcb()
{
  if (xsave.flags) {
    lwpcb.flags = xsave.flags;
    lwpcb.buffer_size = xsave.buffer_size;
    lwpcb.buffer_base = xsave.buffer_base;
    lwpcb.buffer_head_offset = xsave.buffer_head_offset;
    lwpcb.filters = xsave.filters;
    lwpcb.event[LWP_EVENT].counter = xsave.event_counter[LWP_EVENT];
  }

  return true;
}

LWP::LWP(Task *task, pid_t tid)
  : task(task), tid(tid), fd_ticks(-1), started(false),
    last_ticks_period(0), saved_ticks(0), ticks_read(0)
{
  memset(&lwpcb, 0, sizeof lwpcb);
  memset(&xsave, 0, sizeof xsave);

  if (xsave_area_size <= 0) {
    auto cpuid_data = cpuid(CPUID_GETFEATURES, 0);
    if (!(cpuid_data.ecx & (1 << 26))) {
      abort();
      // XSAVE not present
      return;
    }

    // We'll use the largest possible area all the time
    // even when it might not be needed. Simpler that way.
    cpuid_data = cpuid(CPUID_GETXSAVE, 0);
    xsave_area_size = cpuid_data.ecx;
    long xsave_features = ((long)cpuid_data.edx << 32LL) + cpuid_data.eax;

    if (xsave_features & (1LL<<62)) {
      cpuid_data = cpuid(CPUID_GETXSAVE, 62);
      xsave_lwp_size = cpuid_data.eax;
      xsave_lwp_off = cpuid_data.ebx;
    } else {
      abort();
    }
  }
}

LWP::~LWP()
{
  if (fd_ticks != -1)
    fd_ticks.close();
}

static ScopedFd start_ticks(pid_t tid, int group_fd, struct perf_event_attr* attr)
{
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

static struct perf_event_attr ticks_attr;
void LWP::reset(Ticks ticks_period)
{
  assert(ticks_period >= 0);
  assert(ticks_period <= 0xffffff);
  assert(ticks_period <= LWP_INTERVAL);

  start_ticks(tid, -1, &rr::ticks_attr);

  xsave.event_counter[LWP_EVENT] = ticks_period;
  lwpcb.event[LWP_EVENT].counter = ticks_period;
}

void LWP::stop()
{
  lwpcb.flags = 0;
  xsave.flags = 0;

  fd_ticks.close();
}

Ticks LWP::read_ticks_nondestructively()
{
  long counter_value = lwpcb.event[LWP_EVENT].counter;
  if (counter_value & LWP_SIGN)
    counter_value |= LWP_SIGN;
  assert(counter_value >= -2048);
  long diff = last_ticks_period - counter_value;
  assert(diff >= 0);
  long ret = saved_ticks;
  ret += diff;
  return ret;
}

Ticks LWP::read_ticks()
{
  long ticks = read_ticks_nondestructively();
  long ret = ticks - ticks_read;
  ticks_read = ticks;
  return ret;
}

void LWP::adjust(Ticks diff)
{
  ticks_read += diff;
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
  attr->sample_period = 1; /* this is in interrupts */
}

static bool attributes_initialized;

static void init_attributes() {
  if (attributes_initialized) {
    return;
  }
  attributes_initialized = true;

  FILE *f = fopen("/sys/devices/lwp/type", "r");
  if (!f)
    FATAL() << "LWP events not found";

  int type;
  if (fscanf(f, "%d", &type) != 1)
    FATAL() << "LWP events not found";

  fclose(f);

  init_perf_event_attr(&rr::ticks_attr, (perf_type_id)type, 0);
}

const struct perf_event_attr& LWP::ticks_attr() {
  init_attributes();
  return rr::ticks_attr;
}

}
