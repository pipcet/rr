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
#include "AutoRemoteSyscalls.h"
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
#include "ReplaySession.h"

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
  if (disable_lwp && (xsave.flags & 8)) {
    buf[519] &= ~0x40;
    memset(buf + 832 + 32, 0, 32);
    if (!task->ptrace_if_alive(PTRACE_SETREGSET, NT_X86_XSTATE, &vec))
      return false;
  }
  free(buf);

  return ret;
}

bool LWP::lwp_xsave_to_lwpcb()
{
  if (!(xsave.flags != 0 || lwpcb.flags == 0)) {
    LOG(info) << task->registers.ip();
    return true;
  }

  /* Flags should be unchanged.
   *
   * Family 15h revision 00h-0fh: flags 0x80000008 -> 0x00000008
   */
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
  //lwpcb.filters = xsave.filters;
  if (lwpcb.event[LWP_EVENT].counter != xsave.event_counter[LWP_EVENT]) {
    LOG(debug) << "LWP counter changed from " << lwpcb.event[LWP_EVENT].counter << " to " << xsave.event_counter[LWP_EVENT];
  }
  lwpcb.event[LWP_EVENT].counter = xsave.event_counter[LWP_EVENT];

  if (lwpcb.flags != xsave.flags) {
    LOG(warn) << "LWP flags changed from " << lwpcb.flags << " to "
              << xsave.flags << "\n";
    if (lwpcb.flags == 0x80000008 && xsave.flags == 8) {
      LOG(warn) << "this is a known CPU issue";
    } else {
      //ASSERT(task, 0);
      //lwpcb.flags = xsave.flags;
    }
  }
  if (xsave.flags == 0) {
    //fprintf(stderr, "xsave flags reset!\n");
    return true;
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

static ScopedFd start_ticks(pid_t tid __attribute__((unused)),
                            int group_fd __attribute__((unused)),
                            struct perf_event_attr* attr __attribute__((unused)))
{
#if 1
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
#endif
  return fd;
}

int LWP::ticks_fd()
{
  return fd_ticks;
}

bool LWP::is_time_slice_signal(const siginfo_t* si)
{
  if (si->si_signo == SIGSTKFLT)
    return true;

  return si->si_signo == SIGSEGV &&
    si->si_addr == (void *)0x70002000;
}

bool LWP::signal(const siginfo_t* si)
{
  if (is_time_slice_signal(si)) {
    /* XXX is this required? */
    read_lwp_xsave(true);
    return true;
  }

  return false;
}

void LWP::set_tid(pid_t tid)
{
  this->tid = tid;
}

static struct perf_event_attr ticks_attr;
void LWP::reset(Ticks ticks_period)
{
  stop();
  if (ticks_period > LWP_MAX_PERIOD)
    ticks_period = LWP_MAX_PERIOD;
  assert(ticks_period >= 0);
  assert(ticks_period <= LWP_MAX_PERIOD);
  assert(ticks_period <= LWP_INTERVAL);

  if (read_lwp_xsave(true))
    lwp_xsave_to_lwpcb();

  struct perf_event_attr attr = rr::ticks_attr;
  fd_ticks = start_ticks(tid, -1, &attr);

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
    ASSERT(task, diff >= 0) << " bad diff " << diff;
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

#if 1
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
#endif

static bool attributes_initialized;

static void init_attributes() {
  if (attributes_initialized) {
    return;
  }
  attributes_initialized = true;

#if 1
  FILE *f = fopen("/sys/devices/lwp/type", "r");
  if (!f)
    FATAL() << "LWP events not found";

  int type;
  if (fscanf(f, "%d", &type) != 1)
    FATAL() << "LWP events not found";

  fclose(f);

  init_perf_event_attr(&rr::ticks_attr, (perf_type_id)type, 0);
#endif
}

const struct perf_event_attr& LWP::ticks_attr() {
  init_attributes();
  return rr::ticks_attr;
}

bool LWP::set_lwpcb() {
  bool interrupted = false;
  bool restarted = false;
  //  remote_code_ptr last_ip = address_of_last_execution_resume;
 again:
  Registers r = task->regs();
  task->registers.set_ip(RR_PAGE_LWP_THUNK_ENTRY);
  task->set_regs(task->registers);
  while (true) {
    LOG(debug) << "at ip " << r.ip();
    task->resume_execution(RESUME_SINGLESTEP, RESUME_WAIT, RESUME_NO_TICKS, 0, true);
    if (task->is_ptrace_seccomp_event()) {
      LOG(debug) << "aborting set_lwpcb: seccomp event";
      interrupted = true;
      break;
    }
    if (task->ptrace_event()) {
      LOG(debug) << "aborting set_lwpcb: ptrace event: " << ptrace_event_name(task->ptrace_event());
      interrupted = true;
      break;
    }
    if (task->status().group_stop()) {
      /* SIGCONT. See comment in RecordSession.cc. */
      continue;
    }
    if (task->regs().ip() == RR_PAGE_LWP_THUNK ||
        task->regs().ip() == RR_PAGE_LWP_THUNK+1) {
      LOG(debug) << "Interrupted syscall, resetting, " << task->regs().syscallno();
      /* if (stop_sig() == SYSCALLBUF_DESCHED_SIGNAL) {
        LOG(debug) << "discarding SYSCALLBUF_DESCHED_SIGNAL";
        goto restart;
        } */
      if (ReplaySession::is_ignored_signal(task->stop_sig()) &&
          task->session().is_replaying())
        goto restart;
      LOG(debug) << "restarting at ip " << r.ip();
      if (task->stop_sig() && task->stop_sig() != SIGTRAP) {
        LOG(debug) << "signal!";
        interrupted = true;
        break;
      } else if (task->stop_sig()) {
        TrapReasons reasons = task->compute_trap_reasons(task->regs().ip(), task->address_of_last_execution_resume, true);

        if (reasons.watchpoint || reasons.breakpoint || !reasons.singlestep) {
          LOG(debug) << "signal SIGTRAP";
          interrupted = true;
          break;
        }
      }
    restart:
      if (!restarted) {
        r.set_ip(r.ip() - 2);
        restarted = true;
      }
      r.set_syscallno(task->regs().syscallno());
      task->set_regs(r);
      goto again;
    } else {
      /*
      if (stop_sig() == SYSCALLBUF_DESCHED_SIGNAL) {
        LOG(debug) << "discarding SYSCALLBUF_DESCHED_SIGNAL";
        continue;
      }
      */
      if (task->stop_sig() == SIGTRAP) {
        TrapReasons reasons = task->compute_trap_reasons(task->regs().ip(), task->address_of_last_execution_resume, task->ip() == task->address_of_last_execution_resume);

        if (!reasons.breakpoint && !reasons.watchpoint && reasons.singlestep) {
          if (task->regs().ip() == RR_PAGE_LWP_THUNK_END)
            break;
          continue;
        } else {
          LOG(debug) << "interrupted by SIGTRAP";
          interrupted = true;
          break;
        }
      }
    }
    if (!task->stop_sig()) {
      continue;
    }
    if (ReplaySession::is_ignored_signal(task->stop_sig()) &&
        task->session().is_replaying())
      continue;
    /*
    if (stop_sig() == SYSCALLBUF_DESCHED_SIGNAL) {
      LOG(debug) << "discarding SYSCALLBUF_DESCHED_SIGNAL";
      continue;
    }
    */
    interrupted = true;
    break;
  }

  r.set_flags(r.flags() &~ X86_RF_FLAG);
  r.clear_singlestep_flag();
  LOG(debug) << "setregs to ip " << r.ip();
  task->set_regs(r);
  if (restarted) {
  }

  //task->set_debug_status(0);
  if (!interrupted) {
    task->wait_status = WaitStatus();
    task->pending_siginfo.si_code = 0;
  }
  return !interrupted;
}

bool LWP::start_with_interval(Ticks ticks)
{
  init_buffer(AddressSpace::lwp_buffer_start(), AddressSpace::lwp_buffer_size());
  reset(ticks);
  if (write_lwpcb(AddressSpace::lwpcb_start())) {
    read_lwp_xsave(false);
    read_ticks();
    LOG(debug) << "starting LWP";
    if (!set_lwpcb()) {
      return true;
    }
    //task->set_debug_status(0);
  }

  return false;
}

void LWP::init(AddressSpace* as)
{
  if (!inited) {
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;

    {
      AutoRemoteSyscalls remote(task);

      remote.infallible_mmap_syscall(AddressSpace::lwp_area_start(), AddressSpace::lwpcb_size(), prot, flags,
                                     -1, 0);

      remote.infallible_mmap_syscall(AddressSpace::lwp_buffer_start(), AddressSpace::lwp_buffer_size(), PROT_NONE, flags, -1, 0);
    }

    as->map(task, AddressSpace::lwp_area_start(), AddressSpace::lwpcb_size(), prot, flags, 0, "[lwp]",
            KernelMapping::NO_DEVICE, KernelMapping::NO_INODE);
    as->map(task, AddressSpace::lwp_buffer_start(), AddressSpace::lwp_buffer_size(), PROT_NONE, flags, 0, "[lwp]",
            KernelMapping::NO_DEVICE, KernelMapping::NO_INODE);

    init_buffer(AddressSpace::lwp_buffer_start(),
                AddressSpace::lwp_buffer_size());
    write_lwpcb(AddressSpace::lwpcb_start());
    inited = true;
  }
}

Ticks LWP::stop_and_read()
{
  Ticks ret = 0;
  bool disable_lwp = true;
  init_buffer(AddressSpace::lwp_buffer_start(), AddressSpace::lwp_buffer_size());
  if (read_lwp_xsave(disable_lwp)) {
    lwp_xsave_to_lwpcb();
    ret = read_ticks();
  } else {
    LOG(debug) << "LWP disabled";
  }

  return ret;
}

}
