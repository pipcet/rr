/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "record_signal.h"

#include <assert.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/user.h>
#include <syscall.h>
#include <x86intrin.h>

#include "preload/preload_interface.h"

#include "AutoRemoteSyscalls.h"
#include "Flags.h"
#include "PerfCounters.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "TraceStream.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

static __inline__ unsigned long long rdtsc(void) { return __rdtsc(); }

template <typename Arch> static size_t sigaction_sigset_size_arch() {
  return sizeof(typename Arch::kernel_sigset_t);
}

static size_t sigaction_sigset_size(SupportedArch arch) {
  RR_ARCH_FUNCTION(sigaction_sigset_size_arch, arch);
}

/**
 * Restore the blocked-ness and sigaction for |sig| from |t|'s local
 * copy.
 */
static void restore_signal_state(RecordTask* t, int sig) {
  AutoRemoteSyscalls remote(t);
  size_t sigset_size = sigaction_sigset_size(remote.arch());
  {
    const vector<uint8_t>& sa = t->signal_action(sig);
    AutoRestoreMem child_sa(remote, sa.data(), sa.size());
    remote.infallible_syscall(syscall_number_for_rt_sigaction(remote.arch()),
                              sig, child_sa.get().as_int(), nullptr,
                              sigset_size);
  }
  if (t->is_sig_blocked(sig)) {
    vector<uint8_t> bytes;
    bytes.resize(sigset_size);
    memset(bytes.data(), 0, sigset_size);
    uint64_t mask = uint64_t(1) << (sig - 1);
    ASSERT(t, sigset_size >= sizeof(mask));
    memcpy(bytes.data(), &mask, sizeof(mask));
    AutoRestoreMem child_block(remote, bytes.data(), bytes.size());
    remote.infallible_syscall(syscall_number_for_rt_sigprocmask(remote.arch()),
                              SIG_BLOCK, child_block.get().as_int(), nullptr,
                              sigset_size);
  }
}

/** Return true iff |t->ip()| points at a RDTSC instruction. */
static const uint8_t rdtsc_insn[] = { 0x0f, 0x31 };
static bool is_ip_rdtsc(RecordTask* t) {
  uint8_t insn[sizeof(rdtsc_insn)];
  if (sizeof(insn) !=
      t->read_bytes_fallible(t->ip().to_data_ptr<uint8_t>(), sizeof(insn),
                             insn)) {
    return false;
  }
  return !memcmp(insn, rdtsc_insn, sizeof(insn));
}

/**
 * Return true if |t| was stopped because of a SIGSEGV resulting
 * from a rdtsc and |t| was updated appropriately, false otherwise.
 */
static bool try_handle_rdtsc(RecordTask* t, siginfo_t* si) {
  ASSERT(t, si->si_signo == SIGSEGV);

  if (!is_ip_rdtsc(t) || t->tsc_mode == PR_TSC_SIGSEGV) {
    return false;
  }

  unsigned long long current_time = rdtsc();
  Registers r = t->regs();
  r.set_rdtsc_output(current_time);
  r.set_ip(r.ip() + sizeof(rdtsc_insn));
  t->set_regs(r);

  t->push_event(Event(EV_SEGV_RDTSC, HAS_EXEC_INFO, t->arch()));
  LOG(debug) << "  trapped for rdtsc: returning " << current_time;
  return true;
}

/**
 * Return true if |t| was stopped because of a SIGSEGV and we want to retry
 * the instruction after emulating MAP_GROWSDOWN.
 */
static bool try_grow_map(RecordTask* t, siginfo_t* si) {
  ASSERT(t, si->si_signo == SIGSEGV);

  // Use kernel_abi to avoid odd inconsistencies between distros
  auto arch_si = reinterpret_cast<NativeArch::siginfo_t*>(si);
  auto addr = arch_si->_sifields._sigfault.si_addr_.rptr();

  if (t->vm()->has_mapping(addr)) {
    LOG(debug) << "try_grow_map " << addr << ": address already mapped";
    return false;
  }
  auto maps = t->vm()->maps_starting_at(floor_page_size(addr));
  auto it = maps.begin();
  if (it == maps.end()) {
    LOG(debug) << "try_grow_map " << addr << ": no later map to grow downward";
    return false;
  }
  if (!(it->map.flags() & MAP_GROWSDOWN)) {
    LOG(debug) << "try_grow_map " << addr << ": map is not MAP_GROWSDOWN ("
               << it->map << ")";
    return false;
  }
  if (addr >= page_size() && t->vm()->has_mapping(addr - page_size())) {
    LOG(debug) << "try_grow_map " << addr << ": address would be in guard page";
    return false;
  }
  struct rlimit stack_limit;
  remote_ptr<void> limit_bottom;
  int ret = prlimit(t->tid, RLIMIT_STACK, NULL, &stack_limit);
  if (ret >= 0 && stack_limit.rlim_cur != RLIM_INFINITY) {
    limit_bottom = ceil_page_size(it->map.end() - stack_limit.rlim_cur);
    if (limit_bottom > addr) {
      LOG(debug) << "try_grow_map " << addr << ": RLIMIT_STACK exceeded";
      return false;
    }
  }

  // Try to grow by 64K at a time to reduce signal frequency.
  auto new_start = floor_page_size(addr);
  static const uintptr_t grow_size = 0x10000;
  if (it->map.start().as_int() >= grow_size) {
    auto possible_new_start = std::max(
        limit_bottom, std::min(new_start, it->map.start() - grow_size));
    // Ensure that no mapping exists between possible_new_start - page_size()
    // and new_start. If there is, possible_new_start is not valid, in which
    // case we just abandon the optimization.
    if (possible_new_start >= page_size() &&
        !t->vm()->has_mapping(possible_new_start - page_size()) &&
        t->vm()->maps_starting_at(possible_new_start - page_size())
                .begin()
                ->map.start() == it->map.start()) {
      new_start = possible_new_start;
    }
  }
  LOG(debug) << "try_grow_map " << addr << ": trying to grow map " << it->map;

  {
    AutoRemoteSyscalls remote(t, AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS);
    remote.infallible_mmap_syscall(
        new_start, it->map.start() - new_start, it->map.prot(),
        (it->map.flags() & ~MAP_GROWSDOWN) | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  }

  KernelMapping km =
      t->vm()->map(t, new_start, it->map.start() - new_start, it->map.prot(),
                   it->map.flags() | MAP_ANONYMOUS, 0, string(),
                   KernelMapping::NO_DEVICE, KernelMapping::NO_INODE);
  t->trace_writer().write_mapped_region(t, km, km.fake_stat());
  // No need to flush syscallbuf here. It's safe to map these pages "early"
  // before they're really needed.
  t->record_event(Event(EV_GROW_MAP, NO_EXEC_INFO, t->arch()),
                  RecordTask::DONT_FLUSH_SYSCALLBUF);
  t->push_event(Event::noop(t->arch()));
  LOG(debug) << "try_grow_map " << addr << ": extended map "
             << t->vm()->mapping_of(addr).map;
  return true;
}

void disarm_desched_event(RecordTask* t) {
  if (ioctl(t->desched_fd, PERF_EVENT_IOC_DISABLE, 0)) {
    FATAL() << "Failed to disarm desched event";
  }
}

void arm_desched_event(RecordTask* t) {
  if (ioctl(t->desched_fd, PERF_EVENT_IOC_ENABLE, 0)) {
    FATAL() << "Failed to disarm desched event";
  }
}

/**
 * Return the event needing to be processed after this desched of |t|.
 * The tracee's execution may be advanced, and if so |regs| is updated
 * to the tracee's latest state.
 */
static void handle_desched_event(RecordTask* t, const siginfo_t* si) {
  ASSERT(t, (SYSCALLBUF_DESCHED_SIGNAL == si->si_signo &&
             si->si_code == POLL_IN && si->si_fd == t->desched_fd_child))
      << "Tracee is using SIGPWR??? (siginfo=" << *si << ")";

  /* If the tracee isn't in the critical section where a desched
   * event is relevant, we can ignore it.  See the long comments
   * in syscall_buffer.c.
   *
   * It's OK if the tracee is in the critical section for a
   * may-block syscall B, but this signal was delivered by an
   * event programmed by a previous may-block syscall A.
   *
   * If we're running in a signal handler inside an interrupted syscallbuf
   * system call, never do anything here. Syscall buffering is disabled and
   * the desched_signal_may_be_relevant was set by the outermost syscallbuf
   * invocation.
   */
  if (!t->read_mem(REMOTE_PTR_FIELD(t->syscallbuf_child,
                                    desched_signal_may_be_relevant)) ||
      t->running_inside_desched()) {
    LOG(debug) << "  (not entering may-block syscall; resuming)";
    /* We have to disarm the event just in case the tracee
     * has cleared the relevancy flag, but not yet
     * disarmed the event itself. */
    disarm_desched_event(t);
    t->push_event(Event::noop(t->arch()));
    return;
  }

  /* TODO: how can signals interrupt us here? */

  /* The desched event just fired.  That implies that the
   * arm-desched ioctl went into effect, and that the
   * disarm-desched syscall didn't take effect.  Since a signal
   * is pending for the tracee, then if the tracee was in a
   * syscall, linux has exited it with an -ERESTART* error code.
   * That means the tracee is about to (re-)enter either
   *
   *  1. buffered syscall
   *  2. disarm-desched ioctl syscall
   *
   * We can figure out which one by simply issuing a
   * ptrace(SYSCALL) and examining the tracee's registers.
   *
   * If the tracee enters the disarm-desched ioctl, it's going
   * to commit a record of the buffered syscall to the
   * syscallbuf, and we can safely send the tracee back on its
   * way, ignoring the desched completely.
   *
   * If it enters the buffered syscall, then the desched event
   * has served its purpose and we need to prepare the tracee to
   * be context-switched.
   *
   * An annoyance of the desched signal is that when the tracer
   * is descheduled in interval (C) above, we see normally (see
   * below) see *two* signals.  The current theory of what's
   * happening is
   *
   *  o child gets descheduled, bumps counter to i and schedules
   *    signal
   *  o signal notification "schedules" child, but it doesn't
   *    actually run any application code
   *  o child is being ptraced, so we "deschedule" child to
   *    notify parent and bump counter to i+1.  (The parent
   *    hasn't had a chance to clear the counter yet.)
   *  o another counter signal is generated, but signal is
   *    already pending so this one is queued
   *  o parent is notified and sees counter value i+1
   *  o parent stops delivery of first signal and disarms
   *    counter
   *  o second signal dequeued and delivered, notififying parent
   *    (counter is disarmed now, so no pseudo-desched possible
   *    here)
   *  o parent notifiedand sees counter value i+1 again
   *  o parent stops delivery of second signal and we continue on
   *
   * So we "work around" this by the tracer expecting two signal
   * notifications, and silently discarding both.
   *
   * One really fun edge case is that sometimes the desched
   * signal will interrupt the arm-desched syscall itself.
   * Continuing to the next syscall boundary seems to restart
   * the arm-desched syscall, and advancing to the boundary
   * again exits it and we start receiving desched signals
   * again.
   *
   * That may be a kernel bug, but we handle it by just
   * continuing until we we continue past the arm-desched
   * syscall *and* stop seeing signals. */
  while (true) {
    // Prevent further desched notifications from firing
    // while we're advancing the tracee.  We're going to
    // leave it in a consistent state anyway, so the event
    // is no longer useful.  We have to do this in each
    // loop iteration because a restarted arm-desched
    // syscall may have re-armed the event.
    disarm_desched_event(t);

    t->resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_UNLIMITED_TICKS);

    if (t->status().is_syscall()) {
      if (t->is_arm_desched_event_syscall()) {
        continue;
      }
      break;
    }

    // Completely ignore spurious desched signals and
    // signals that aren't going to be delivered to the
    // tracee.
    //
    // Also ignore time-slice signals.  If the tracee ends
    // up at the disarm-desched ioctl, we'll reschedule it
    // with the ticks interrupt still programmed.  At worst,
    // the tracee will get an extra time-slice out of
    // this, on average, so we don't worry too much about
    // it.
    //
    // TODO: it's theoretically possible for this to
    // happen an unbounded number of consecutive times
    // and the tracee never switched out.
    int sig = t->stop_sig();
    ASSERT(t, sig) << "expected stop-signal, got " << t->status();
    if (SYSCALLBUF_DESCHED_SIGNAL == sig ||
        t->is_time_slice_signal() || t->is_sig_ignored(sig)) {
      LOG(debug) << "  dropping ignored " << signal_name(sig);
      continue;
    }

    LOG(debug) << "  stashing " << signal_name(sig);
    t->stash_sig();
  }

  if (t->is_disarm_desched_event_syscall()) {
    LOG(debug)
        << "  (at disarm-desched, so finished buffered syscall; resuming)";
    t->push_event(Event::noop(t->arch()));
    return;
  }

  if (t->desched_rec()) {
    // We're already processing a desched. We probably reexecuted the
    // system call (e.g. because a signal was processed) and the syscall
    // blocked again. Carry on with the current desched.
  } else {
    /* This prevents the syscallbuf record counter from being
     * reset until we've finished guiding the tracee through this
     * interrupted call.  We use the record counter for
     * assertions. */
    t->delay_syscallbuf_reset = true;

    /* The tracee is (re-)entering the buffered syscall.  Stash
     * away this breadcrumb so that we can figure out what syscall
     * the tracee was in, and how much "scratch" space it carved
     * off the syscallbuf, if needed. */
    remote_ptr<const struct syscallbuf_record> desched_rec =
        t->next_syscallbuf_record();
    t->push_event(DeschedEvent(desched_rec, t->arch()));
    int call = t->read_mem(REMOTE_PTR_FIELD(t->desched_rec(), syscallno));

    /* The descheduled syscall was interrupted by a signal, like
     * all other may-restart syscalls, with the exception that
     * this one has already been restarted (which we'll detect
     * back in the main loop). */
    t->push_event(Event(interrupted, SyscallEvent(call, t->arch())));
    SyscallEvent& ev = t->ev().Syscall();
    ev.desched_rec = desched_rec;
  }

  SyscallEvent& ev = t->ev().Syscall();
  ev.regs = t->regs();
  /* For some syscalls (at least poll) but not all (at least not read),
   * repeated cont_syscall()s above of the same interrupted syscall
   * can set $orig_eax to 0 ... for unclear reasons. Fix that up here
   * otherwise we'll get a divergence during replay, which will not
   * encounter this problem.
   */
  int call = t->read_mem(REMOTE_PTR_FIELD(t->desched_rec(), syscallno));
  ev.regs.set_original_syscallno(call);
  t->set_regs(ev.regs);
  // runnable_state_changed will observe us entering this syscall and change
  // state to ENTERING_SYSCALL

  LOG(debug) << "  resuming (and probably switching out) blocked `"
             << t->syscall_name(call) << "'";
}

static bool is_safe_to_deliver_signal(RecordTask* t, siginfo_t* si) {
  if (!t->is_in_syscallbuf()) {
    /* The tracee is outside the syscallbuf code,
     * so in most cases can't possibly affect
     * syscallbuf critical sections.  The
     * exception is signal handlers "re-entering"
     * desched'd syscalls, which are OK. */
    LOG(debug) << "Safe to deliver signal at " << t->ip()
               << " because not in syscallbuf";
    return true;
  }

  if (t->is_in_traced_syscall()) {
    LOG(debug) << "Safe to deliver signal at " << t->ip()
               << " because in traced syscall";
    return true;
  }

  if (t->is_in_untraced_syscall() && t->desched_rec()) {
    LOG(debug) << "Safe to deliver signal at " << t->ip()
               << " because tracee interrupted by desched of "
               << t->syscall_name(t->read_mem(
                      REMOTE_PTR_FIELD(t->desched_rec(), syscallno)));
    return true;
  }

  if (t->is_in_untraced_syscall() && si->si_signo == SIGSYS &&
      si->si_code == SYS_SECCOMP) {
    LOG(debug) << "Safe to deliver signal at " << t->ip()
               << " because signal is seccomp trap.";
    return true;
  }

  // If the syscallbuf buffer hasn't been created yet, just delay the signal
  // with no need to set notify_on_syscall_hook_exit; the signal will be
  // delivered when rrcall_init_buffers is called.
  if (t->syscallbuf_child) {
    // Our emulation of SYS_rrcall_notify_syscall_hook_exit clears this flag.
    t->write_mem(
        REMOTE_PTR_FIELD(t->syscallbuf_child, notify_on_syscall_hook_exit),
        (uint8_t)1);
  }

  LOG(debug) << "Not safe to deliver signal at " << t->ip();
  return false;
}

SignalHandled handle_signal(RecordTask* t, siginfo_t* si,
                            SignalDeterministic deterministic) {
  LOG(debug) << t->tid << ": handling signal " << signal_name(si->si_signo)
             << " (pevent: " << ptrace_event_name(t->ptrace_event())
             << ", event: " << t->ev();

  /* We have to check for a desched event first, because for
   * those we *do not* want to (and cannot, most of the time)
   * step the tracee out of the syscallbuf code before
   * attempting to deliver the signal. */
  if (SYSCALLBUF_DESCHED_SIGNAL == si->si_signo) {
    handle_desched_event(t, si);
    return SIGNAL_HANDLED;
  }

  if (!is_safe_to_deliver_signal(t, si)) {
    return DEFER_SIGNAL;
  }

  if (!t->set_siginfo_for_synthetic_SIGCHLD(si)) {
    return DEFER_SIGNAL;
  }

  int sig = si->si_signo;
  // When a deterministic signal is triggered, but the signal is currently
  // blocked or ignored, the kernel (in |force_sig_info|) unblocks it and
  // sets its disposition to SIG_DFL. It never undoes this (probably
  // because it expects the signal to be fatal, which it always would be
  // unless a ptracer intercepts the signal as we do). Therefore, if the signal
  // was generated for rr's purposes, we need to restore the signal state
  // ourselves. If the signal was not generated for rr's purposes, we'll
  // modify our copy of the signal state to match what the kernel did.

  if (t->ts->signal(si)) {
      t->push_event(Event(EV_SCHED, HAS_EXEC_INFO, t->arch()));
    if (si->si_signo == SIGSEGV && t->is_sig_blocked(SIGSEGV))
      restore_signal_state(t, sig);

    return SIGNAL_HANDLED;
  }

  /* See if this signal occurred because of an rr implementation detail,
   * and fudge t appropriately. */
  switch (sig) {
    case SIGSEGV:
      if (deterministic == DETERMINISTIC_SIG &&
          (try_handle_rdtsc(t, si) || try_grow_map(t, si))) {
        if (t->is_sig_blocked(sig) || t->is_sig_ignored(sig)) {
          restore_signal_state(t, sig);
        }
        return SIGNAL_HANDLED;
      }
      break;
  }

  if (deterministic == DETERMINISTIC_SIG &&
      (t->is_sig_blocked(sig) || t->is_sig_ignored(sig))) {
    t->set_sig_blocked(sig, false);
    t->set_sig_handler_default(sig);
  }

  /* This signal was generated by the program or an external
   * source, record it normally. */

  if (t->emulate_ptrace_stop(WaitStatus::for_stop_sig(sig), si)) {
    // Record an event so that replay progresses the tracee to the
    // current point before we notify the tracer.
    // If the signal is deterministic, record it as an EV_SIGNAL so that
    // we replay it using the deterministic-signal replay path. This is
    // more efficient than emulate_async_signal. Also emulate_async_signal
    // currently assumes it won't encounter a deterministic SIGTRAP (due to
    // a hardcoded breakpoint in the tracee).
    if (deterministic == DETERMINISTIC_SIG) {
      t->push_event(SignalEvent(*si, deterministic, t));
      t->record_current_event();
      t->pop_event(EV_SIGNAL);
    } else {
      t->push_event(Event(EV_SCHED, HAS_EXEC_INFO, t->arch()));
      t->record_current_event();
      t->pop_event(EV_SCHED);
    }
    // ptracer has been notified, so don't deliver the signal now.
    // The signal won't be delivered for real until the ptracer calls
    // PTRACE_CONT with the signal number (which we don't support yet!).
    return SIGNAL_PTRACE_STOP;
  }

  t->push_event(SignalEvent(*si, deterministic, t));
  return SIGNAL_HANDLED;
}

} // namespace rr
