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

#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <algorithm>
#include <string>

#include "Flags.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"

#include "Task.h"

#include <asm/prctl.h>
#include <asm/ptrace.h>
#include <elf.h>
#include <errno.h>
#include <limits.h>
#include <linux/ipc.h>
#include <linux/net.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>

#include <limits>
#include <set>
#include <sstream>

#include <rr/rr.h>

#include "preload/preload_interface.h"

#include "AutoRemoteSyscalls.h"
#include "CPUIDBugDetector.h"
#include "MagicSaveDataMonitor.h"
#include "PreserveFileMonitor.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "ReplaySession.h"
#include "ScopedFd.h"
#include "StdioMonitor.h"
#include "StringVectorToCharArray.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "kernel_supplement.h"
#include "log.h"
#include "record_signal.h"
#include "seccomp-bpf.h"
#include "util.h"
#include "LWP.h"

using namespace std;

namespace rr {

PerfCounters::PerfCounters(pid_t tid) : tid(tid), started(false) {
}

unsigned long buffer[1024];
unsigned long realbuffer[1024];
unsigned long last_ticks_period;
unsigned long saved_ticks;
unsigned long ticks_read;

void PerfCounters::reset(Ticks ticks_period) {
  stop();

  //fprintf(stderr, "starting with ticks = %ld\n", ticks_period);

  unsigned long data[256];
  struct iovec iov;
  iov.iov_base = data;
  iov.iov_len = sizeof data;
  while (ptrace(PTRACE_GETREGSET, tid, NT_X86_XSTATE, &iov) == -1);
  saved_ticks = read_ticks_nondestructively(data);
  last_ticks_period = ticks_period;
  //printf("len %ld\n", iov.iov_len);
  int i;
  for (i = 104; i < 104 + 128/8; i++)
    //fprintf(stderr, "%d: %016lx\n", i, data[i]);
    ;
  if (data[104]) {
    data[105] |= 0x80000008LL;
    data[113] = (ticks_period);
    data[107] = (data[107] & 0xffffffff) | 0x2800000000000000L;
  } else {
    last_ticks_period = 0x1000000;
    saved_ticks = 454744 - 1365 + (911554 - 455777);
  }
  while (ptrace(PTRACE_SETREGSET, tid, NT_X86_XSTATE, &iov) == -1);
  //fprintf(stderr, "started with saved_ticks = %ld, last_ticks_period = %ld\n",
  //          (long)saved_ticks, (long) last_ticks_period);
  while (ptrace(PTRACE_GETREGSET, tid, NT_X86_XSTATE, &iov) == -1);
  //printf("len %ld\n", iov.iov_len);
  for (i = 104; i < 104 + 128/8; i++)
    //fprintf(stderr, "%d: %016lx\n", i, data[i]);;
    ;
    
  started = true;
}

void PerfCounters::stop() {
  if (!started) {
    return;
  }
  started = false;

  unsigned long data[256];
  struct iovec iov;
  iov.iov_base = data;
  iov.iov_len = sizeof data;
  while (ptrace(PTRACE_GETREGSET, tid, NT_X86_XSTATE, &iov) == -1);
  //fprintf(stderr, "stopped with ticks = %ld\n", read_ticks_nondestructively(data));
  saved_ticks = read_ticks_nondestructively(data);
  last_ticks_period = 0;
  //printf("len %ld\n", iov.iov_len);
  int i;
  for (i = 104; i < 104 + 128/8; i++)
    ;//fprintf(stderr, "%d: %016lx\n", i, data[i]);
  data[105] &= /* ~4LL */ ~8LL;
  data[113] = 0;
  while (ptrace(PTRACE_SETREGSET, tid, NT_X86_XSTATE, &iov) == -1);
  //fprintf (stderr, "stopped. saved_ticks = %ld\n", (long)saved_ticks);
}

Ticks PerfCounters::read_ticks() {
  unsigned long data[256];
  struct iovec iov;
  iov.iov_base = data;
  iov.iov_len = sizeof data;
  while (ptrace(PTRACE_GETREGSET, tid, NT_X86_XSTATE, &iov) == -1);
  long ticks = read_ticks_nondestructively(data);
  long ret = ticks - ticks_read;
  ticks_read = ticks;
  return ret < 0 ? 0 : ret;
}

Ticks PerfCounters::read_ticks_nondestructively(unsigned long *data) {
  if (data[104] && (data[105] & 8)) {
    long counter_value = data[113] & 0xfffffffff; // data[112]>>32;
    //fprintf(stderr, "read counter at %ld\n", counter_value);
    long ret = saved_ticks;
    if (counter_value & 0x1000000)
      ret += (0x2000000 - counter_value) + last_ticks_period;
    else
      ret +=last_ticks_period - counter_value;
    return ret;
  } else {
    //fprintf(stderr, "counter disabled, returning %ld\n", saved_ticks);
    return saved_ticks;
  }
}

PerfCounters::Extra PerfCounters::read_extra() {
  assert(extra_perf_counters_enabled());

  Extra extra;
  memset(&extra, 0, sizeof(extra));
  return extra;
}

} // namespace rr
