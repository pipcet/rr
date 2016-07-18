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
bool LWP::init_buffer(remote_ptr<void> buffer, size_t buffer_size)
{
  assert(buffer);
  assert(buffer_size >= 32 * 32);
  assert(buffer_size % 32 == 0);

  if (lwpcb.buffer_base == 0) {
    memset(&lwpcb, 0, sizeof lwpcb);
    lwpcb.flags = LWP_FLAGS;
    lwpcb.buffer_size = buffer_size;
    lwpcb.buffer_base = buffer.as_int();
    lwpcb.filters = LWP_FILTERS;
    lwpcb.event[LWP_EVENT].interval = LWP_INTERVAL;
    lwpcb.buffer_head_offset = lwpcb.buffer_tail_offset = 0;

    memset(&xsave, 0, sizeof xsave);
    xsave.flags = LWP_FLAGS;
    xsave.buffer_size = buffer_size;
    xsave.buffer_base = buffer.as_int();
    xsave.filters = LWP_FILTERS;
    xsave.buffer_head_offset = 0;

    return true;
  }

  return true;
}

bool LWP::write_lwpcb(remote_ptr<struct lwpcb> dest_lwp)
{
  if (task->arch() == rr::SupportedArch::x86_64) {
    remote_ptr<long> dest = remote_ptr<long>(dest_lwp.as_int());
    long *src = (long *)&lwpcb;
    assert(task);
    assert(dest);

    unsigned int i;
    for (i = 0; i < (sizeof(lwpcb) + 7) / 8; i++) {
      if (task->fallible_ptrace(PTRACE_POKEDATA, dest + i, reinterpret_cast<void*>(src[i])) != 0)
        return false;
    }
  } else if (task->arch() == rr::SupportedArch::x86) {
    remote_ptr<int> dest = remote_ptr<int>(dest_lwp.as_int());
    int *src = (int *)&lwpcb;
    assert(task);
    assert(dest);

    unsigned int i;
    for (i = 0; i < (sizeof(lwpcb) + 3) / 4; i++) {
      if (task->fallible_ptrace(PTRACE_POKEDATA, dest + i, reinterpret_cast<void*>(src[i])) != 0)
        return false;
    }
  }

  return true;
}

unsigned LWP::xsave_area_size = 0;
unsigned LWP::xsave_lwp_size = 0;
unsigned LWP::xsave_lwp_off = 0;

bool LWP::read_lwp_xsave(bool disable_lwp)
{
  char *buf = (char *)malloc(xsave_area_size);
  bool ret;
  if (!buf)
    return false;
  struct iovec vec = { buf, xsave_area_size };
  if (!task->ptrace_if_alive(PTRACE_GETREGSET, NT_X86_XSTATE, &vec))
    return false;
  if (vec.iov_len != xsave_area_size)
    return false;
  ret = (buf[519] & 0x40) != 0;
  memcpy(&xsave, buf + xsave_lwp_off, sizeof xsave);
  if (disable_lwp) {
    buf[519] &= ~0x40;
    if (!task->ptrace_if_alive(PTRACE_SETREGSET, NT_X86_XSTATE, &vec))
      return false;
  }
  free(buf);

  return ret;
}

bool LWP::lwp_xsave_to_lwpcb()
{
  if (xsave.flags) {
    /* Flags should be unchanged.
     *
     * Family 15h revision 00h-0fh: flags 0x80000008 -> 0x00000008
     */
    if (lwpcb.flags != xsave.flags) {
      LOG(info) << "LWP flags changed from " << lwpcb.flags << " to "
                << xsave.flags << "\n";
      if (lwpcb.flags == 0x80000008 && xsave.flags == 8) {
        LOG(info) << "this is a known CPU issue";
      } else {
        lwpcb.flags = xsave.flags;
      }
    }
    assert(lwpcb.buffer_size == xsave.buffer_size);
    assert(lwpcb.buffer_base == xsave.buffer_base);
    /* Family 15h revision 00h-0fh: filters reset to 0x38000000 if flags = 0
     * Family 15h revision 30h-3fh: filters reset to 0x38000000 if flags = 0
     */
    if (lwpcb.filters != xsave.filters) {
      LOG(info) << "LWP filters changed from " << lwpcb.filters << " to "
                << xsave.filters << "\n";
    }

    lwpcb.buffer_size = xsave.buffer_size;
    lwpcb.buffer_base = xsave.buffer_base;
    if (lwpcb.buffer_head_offset != xsave.buffer_head_offset) {
      LOG(debug) << "LWP buffer head offset changed from " << lwpcb.buffer_head_offset << " to " << xsave.buffer_head_offset;
    }
    lwpcb.buffer_head_offset = xsave.buffer_head_offset;
    lwpcb.filters = xsave.filters;
    if (lwpcb.event[LWP_EVENT].counter != xsave.event_counter[LWP_EVENT]) {
      LOG(debug) << "LWP counter changed from " << lwpcb.event[LWP_EVENT].counter << " to " << xsave.event_counter[LWP_EVENT];
    }
    lwpcb.event[LWP_EVENT].counter = xsave.event_counter[LWP_EVENT];
  }

  return true;
}

static void init_attributes();

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

  init_attributes();
  lwpcb.buffer_base = 0;
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
  if (ticks_period > LWP_MAX_PERIOD)
    ticks_period = LWP_MAX_PERIOD;
  assert(ticks_period >= 0);
  assert(ticks_period <= LWP_MAX_PERIOD);
  assert(ticks_period <= LWP_INTERVAL);

  struct perf_event_attr attr = rr::ticks_attr;
  fd_ticks = start_ticks(tid, -1, &attr);

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

  xsave.event_counter[LWP_EVENT] = ticks_period;
  lwpcb.event[LWP_EVENT].counter = ticks_period;
  last_ticks_period = ticks_period;

  lwpcb.buffer_head_offset = lwpcb.buffer_tail_offset = 0;
  xsave.buffer_head_offset = 0;

  started = true;
  LOG(debug) << "fd open: " << saved_ticks << ", " << task->rr_page_mapped();
}

void LWP::stop()
{
  if (started) {
    read_ticks();
    saved_ticks = ticks_read;
    LOG(debug) << "fd closed: " << saved_ticks << ", " << task->rr_page_mapped();
    fd_ticks.close();
    started = false;
  }
}

Ticks LWP::read_ticks_nondestructively()
{
  if (started) {
    long counter_value = lwpcb.event[LWP_EVENT].counter;
    if (counter_value & LWP_SIGN)
      counter_value |= LWP_SIGN;
    assert(counter_value >= -2048);
    long diff = last_ticks_period - counter_value;
    assert(diff >= 0);
    long ret = saved_ticks;
    ret += diff;
    return ret;
  } else {
    return saved_ticks;
  }
}

Ticks LWP::read_ticks()
{
  long ticks = read_ticks_nondestructively();
  long ret = ticks - ticks_read;
  ticks_read = ticks;
  return ret;
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
